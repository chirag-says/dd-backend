import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  createSavedSearch,
  getMySavedSearches,
  toggleSavedSearchActive,
  deleteSavedSearch,
  updateSavedSearch,
} from "../controllers/savedSearchController.js";
import {
  validateSavedSearchCreate,
  validateMongoId,
} from "../middleware/validators/index.js";

const router = express.Router();

// All saved-search endpoints require auth
router.use(authMiddleware);

// Create saved search (with validation)
router.post("/", validateSavedSearchCreate, createSavedSearch);

// Get user's saved searches
router.get("/mine", getMySavedSearches);

// Toggle saved search active status
router.patch("/:id/toggle", validateMongoId('id'), toggleSavedSearchActive);

// Update saved search settings
router.put("/:id", validateMongoId('id'), updateSavedSearch);

// Delete saved search
router.delete("/:id", validateMongoId('id'), deleteSavedSearch);

export default router;

