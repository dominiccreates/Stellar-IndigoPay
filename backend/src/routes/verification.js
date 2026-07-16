/**
 * src/routes/verification.js — Project verification requests
 *
 * Climate organisations use the /apply form on the frontend to ask the
 * Stellar-IndigoPay admin team to verify a project. This router accepts the
 * submission, persists it to the `verification_requests` table, and
 * fires an admin notification email through services/email.js.
 *
 * Public surface:
 *   - POST /api/verification-requests   Submit a new request (open).
 *   - GET  /api/verification-requests/me
 *       Existing rows indexed by wallet; lets the submitter check the
 *       status of their request without admin credentials. Filters by
 *       ?wallet=Gxxxxxxx.
 *   - GET  /api/verification-requests/:id   Read a single row (admin-only
 *       unless the caller supplies ?wallet=Gxxx matching wallet_address,
 *       so submitters can re-fetch their own submission).
 *   - GET  /api/verification-requests       List all rows (admin-only).
 *   - PATCH /api/verification-requests/:id/status   Approve / reject.
 *       Body: { status: "in_review" | "approved" | "rejected",
 *               reviewerNotes?: string, reviewerBy?: string }
 *
 * Admin endpoints expect a Bearer JWT issued by /api/admin/login, the same
 * mechanism already used by projects.admin/register (see middleware/auth.js).
 */
"use strict";

const express = require("express");
const router = express.Router();
const { v4: uuid } = require("uuid");
const { z } = require("zod");
const pool = require("../db/pool");
const { adminRequired } = require("../middleware/auth");
const { validate } = require("../middleware/validate");
const {
  verificationSchema,
  stellarAddress,
} = require("../validators/schemas");
const { logAdminAction } = require("../services/audit");
const { createRateLimiter } = require("../middleware/rateLimiter");
const { sendAdminVerificationNotification } = require("../services/email");
const { backendName } = require("../services/storage");

const submitLimiter = createRateLimiter(10, 15); // 10 submissions / 15 min / IP

const VALID_TRANSITIONS = {
  pending: ["in_review", "rejected"],
  in_review: ["approved", "rejected", "pending"],
  approved: [],
  rejected: ["pending"],
};

function mapRequestRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    organizationName: row.organization_name,
    organizationWebsite: row.organization_website || null,
    organizationCountry: row.organization_country || null,
    contactEmail: row.contact_email,
    walletAddress: row.wallet_address,
    projectName: row.project_name,
    projectCategory: row.project_category,
    projectLocation: row.project_location,
    projectDescription: row.project_description || null,
    co2PerXLM: row.co2_per_xlm?.toString
      ? row.co2_per_xlm.toString()
      : String(row.co2_per_xlm || "0"),
    expectedAnnualTonnesCO2: row.expected_annual_tonnes_co2?.toString
      ? row.expected_annual_tonnes_co2.toString()
      : row.expected_annual_tonnes_co2
        ? String(row.expected_annual_tonnes_co2)
        : null,
    supportingDocuments: row.supporting_documents || [],
    storageBackend: row.storage_backend,
    notes: row.notes || null,
    status: row.status,
    reviewerNotes: row.reviewer_notes || null,
    reviewedBy: row.reviewed_by || null,
    submittedAt: row.submitted_at
      ? new Date(row.submitted_at).toISOString()
      : null,
    reviewedAt: row.reviewed_at
      ? new Date(row.reviewed_at).toISOString()
      : null,
  };
}

/**
 * POST /api/verification-requests
 * Public. Persists the submission and notifies admins by email.
 */
router.post("/", submitLimiter, validate(verificationSchema), async (req, res, next) => {
  try {
    const body = req.body;
    const id = uuid();
    const result = await pool.query(
      `INSERT INTO verification_requests (
         id, organization_name, organization_website, organization_country,
         contact_email, wallet_address, project_name, project_category,
         project_location, project_description, co2_per_xlm,
         expected_annual_tonnes_co2, supporting_documents, storage_backend, notes
       ) VALUES (
         $1, $2, $3, $4,
         $5, $6, $7, $8,
         $9, $10, $11,
         $12, $13::jsonb, $14, $15
       ) RETURNING *`,
      [
        id,
        body.organizationName.trim(),
        body.organizationWebsite?.trim() || null,
        body.organizationCountry?.trim() || null,
        body.contactEmail.trim().toLowerCase(),
        body.walletAddress,
        body.projectName.trim(),
        body.projectCategory,
        body.projectLocation.trim(),
        body.projectDescription?.trim() || null,
        Number.parseFloat(body.co2PerXLM).toFixed(7),
        body.expectedAnnualTonnesCO2 != null && body.expectedAnnualTonnesCO2 !== ""
          ? Number.parseFloat(body.expectedAnnualTonnesCO2).toFixed(7)
          : null,
        JSON.stringify(body.supportingDocuments),
        backendName(),
        body.notes?.trim() || null,
      ],
    );

    const created = mapRequestRow(result.rows[0]);

    // Fire-and-forget admin notification; failures here must NOT block the
    // persist + 201 success path. The submitter still gets their receipt.
    sendAdminVerificationNotification(created).catch((err) => {
      // eslint-disable-next-line no-console
      console.error("[verification] admin notification failed:", err.message);
    });

    res.status(201).json({
      success: true,
      data: {
        ...created,
        reviewTimeline: "5–10 business days",
      },
    });
  } catch (e) {
    next(e);
  }
});

/**
 * GET /api/verification-requests/me?wallet=Gxxx
 * Public. Returns the request rows owned by the queried wallet (most recent
 * first). Lets submitters check status without admin auth. Capped at 50.
 */
router.get(
  "/me",
  validate(z.object({ wallet: stellarAddress }), "query"),
  async (req, res, next) => {
    try {
      const wallet = req.query.wallet;
      const result = await pool.query(
      `SELECT * FROM verification_requests
        WHERE wallet_address = $1
        ORDER BY submitted_at DESC
        LIMIT 50`,
      [wallet],
    );
    res.json({ success: true, data: result.rows.map(mapRequestRow) });
  } catch (e) {
    next(e);
  }
});

/**
 * GET /api/verification-requests/:id
 * Public, but only returns the row if wallet query param matches
 * the row's wallet_address. Admins can pass ?wallet to bypass this check
 * using the Bearer token.
 */
router.get("/:id", async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT * FROM verification_requests WHERE id = $1",
      [req.params.id],
    );
    const row = result.rows[0];
    if (!row)
      return res.status(404).json({ error: "Verification request not found" });

    // Allow admin-readable without wallet guard.
    const auth = req.headers.authorization || "";
    if (auth.startsWith("Bearer ")) {
      try {
        const { verifyToken } = require("../middleware/auth");
        const decoded = verifyToken(auth.slice(7));
        if (decoded && decoded.role === "admin") {
          return res.json({ success: true, data: mapRequestRow(row) });
        }
      } catch (_err) {
        // fall through to wallet check
      }
    }

    const wallet =
      typeof req.query.wallet === "string" ? req.query.wallet.trim() : "";
    if (!wallet || wallet !== row.wallet_address) {
      return res.status(403).json({
        error: "Provide a matching ?wallet= query param to view this request",
      });
    }
    res.json({ success: true, data: mapRequestRow(row) });
  } catch (e) {
    next(e);
  }
});

/**
 * GET /api/verification-requests
 * Admin only. Returns the most recent submissions with optional filters.
 */
router.get("/", adminRequired, async (req, res, next) => {
  try {
    const { status, limit = "50", page = "1" } = req.query;
    const where = [];
    const values = [];

    if (status && Object.keys(VALID_TRANSITIONS).includes(status)) {
      values.push(status);
      where.push(`status = $${values.length}`);
    }

    const pageSize = Math.min(Number.parseInt(limit, 10) || 50, 200);
    const offset = (Math.max(Number.parseInt(page, 10) || 1, 1) - 1) * pageSize;
    values.push(pageSize, offset);

    let query = "SELECT * FROM verification_requests";
    if (where.length) query += " WHERE " + where.join(" AND ");
    query += ` ORDER BY submitted_at DESC LIMIT $${values.length - 1} OFFSET $${values.length}`;

    // Dynamic WHERE is safe: conditions are built from parameterised $N
    // placeholders with user values passed via `values` array.
    // eslint-disable-next-line sql-injection/no-sql-injection
    const result = await pool.query(query, values);
    res.json({
      success: true,
      data: result.rows.map(mapRequestRow),
      page: Number.parseInt(page, 10),
      pageSize,
    });
  } catch (e) {
    next(e);
  }
});

/**
 * PATCH /api/verification-requests/:id/status
 * Admin only. Transitions the row's status and records reviewer notes.
 */
router.patch("/:id/status", adminRequired, async (req, res, next) => {
  try {
    const { status, reviewerNotes, reviewedBy } = req.body || {};
    if (!status || !Object.keys(VALID_TRANSITIONS).includes(status)) {
      return res.status(400).json({
        error: `status must be one of: ${Object.keys(VALID_TRANSITIONS).join(", ")}`,
      });
    }
    const reviewerNotesStr =
      typeof reviewerNotes === "string" && reviewerNotes.trim()
        ? reviewerNotes.trim()
        : null;
    if (reviewerNotesStr && reviewerNotesStr.length > 2000) {
      return res
        .status(400)
        .json({ error: "reviewerNotes must be at most 2000 characters" });
    }

    const existing = await pool.query(
      "SELECT * FROM verification_requests WHERE id = $1",
      [req.params.id],
    );
    const row = existing.rows[0];
    if (!row)
      return res.status(404).json({ error: "Verification request not found" });

    const transitions = VALID_TRANSITIONS[row.status] || [];
    if (row.status === status) {
      return res
        .status(400)
        .json({ error: `Request is already in "${status}" state` });
    }
    if (!transitions.includes(status)) {
      return res.status(400).json({
        error: `Cannot transition from "${row.status}" to "${status}"`,
      });
    }

    const actor = (req.admin && req.admin.sub) || reviewedBy || "admin";
    const updated = await pool.query(
      `UPDATE verification_requests
          SET status = $1,
              reviewer_notes = $2,
              reviewed_by = $3,
              reviewed_at = NOW()
        WHERE id = $4
        RETURNING *`,
      [status, reviewerNotesStr, actor, req.params.id],
    );

    logAdminAction({
      actor,
      action: `verification.${status}`,
      targetType: "verification_request",
      targetId: req.params.id,
      metadata: {
        fromStatus: row.status,
        toStatus: status,
        reviewerNotes: reviewerNotesStr,
      },
      ipAddress: req.ip,
    });

    res.json({ success: true, data: mapRequestRow(updated.rows[0]) });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
