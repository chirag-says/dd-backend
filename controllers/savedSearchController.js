import SavedSearch from "../models/SavedSearch.js";
import Notification from "../models/Notification.js";
import mongoose from "mongoose";

// ============================================
// SECURITY: Allowed fields for saved searches
// ============================================
const ALLOWED_SAVED_SEARCH_FIELDS = ['name', 'filters', 'notifyEmail', 'notifyInApp'];

/**
 * Sanitize saved search data - only allow whitelisted fields
 */
const sanitizeSavedSearchData = (data) => {
  const sanitized = {};
  for (const field of ALLOWED_SAVED_SEARCH_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(data, field)) {
      sanitized[field] = data[field];
    }
  }
  return sanitized;
};

// Create a new saved search for logged-in user
export const createSavedSearch = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Sanitize input - only allow whitelisted fields
    const sanitizedData = sanitizeSavedSearchData(req.body);
    const { name, filters, notifyEmail = true, notifyInApp = true } = sanitizedData;

    if (!name || !filters) {
      return res.status(400).json({ success: false, message: "Name and filters are required" });
    }

    const hasAnyFilter =
      (filters.search && filters.search.trim()) ||
      filters.city ||
      filters.propertyType ||
      filters.priceRange ||
      filters.availableFor;

    if (!hasAnyFilter) {
      return res.status(400).json({
        success: false,
        message: "At least one filter (city, type, price, etc.) is required to save a search",
      });
    }

    const saved = await SavedSearch.create({
      user: userId, // ALWAYS set from authenticated user, never from request
      name: String(name).substring(0, 100), // Limit name length
      filters: {
        search: String(filters.search || "").substring(0, 200),
        city: String(filters.city || "").substring(0, 100),
        propertyType: String(filters.propertyType || "").substring(0, 50),
        priceRange: String(filters.priceRange || "").substring(0, 20),
        availableFor: String(filters.availableFor || "").substring(0, 20),
      },
      notifyEmail: Boolean(notifyEmail),
      notifyInApp: Boolean(notifyInApp),
    });

    // Create a simple notification for the user
    try {
      await Notification.create({
        user: userId,
        title: "Search saved",
        message: `We will alert you when new properties match: ${name}`,
        type: "saved-search",
        data: { savedSearchId: saved._id },
      });
    } catch (notifyErr) {
      console.error("Notification create error (saved search):", notifyErr);
    }

    return res.status(201).json({ success: true, savedSearch: saved });
  } catch (err) {
    console.error("createSavedSearch error:", err);
    return res.status(500).json({ success: false, message: "Failed to save search" });
  }
};

// Get current user's saved searches
export const getMySavedSearches = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // IDOR Protection: Only fetch searches owned by the authenticated user
    const searches = await SavedSearch.find({ user: userId, isActive: true })
      .sort({ updatedAt: -1 })
      .lean();

    return res.json({ success: true, searches });
  } catch (err) {
    console.error("getMySavedSearches error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch saved searches" });
  }
};

// Soft-disable a saved search (stop alerts)
export const toggleSavedSearchActive = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { id } = req.params;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid saved search ID" });
    }

    // ============================================
    // IDOR PROTECTION: Verify ownership from database
    // Never trust IDs from request body
    // ============================================
    const search = await SavedSearch.findById(id);

    if (!search) {
      return res.status(404).json({ success: false, message: "Saved search not found" });
    }

    // Verify ownership - compare database record's user with authenticated user
    if (search.user.toString() !== userId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${userId} tried to toggle search owned by ${search.user}`);
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    search.isActive = !search.isActive;
    await search.save();

    return res.json({ success: true, savedSearch: search });
  } catch (err) {
    console.error("toggleSavedSearchActive error:", err);
    return res.status(500).json({ success: false, message: "Failed to update saved search" });
  }
};

// Delete a saved search (hard delete with ownership verification)
export const deleteSavedSearch = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { id } = req.params;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid saved search ID" });
    }

    // ============================================
    // IDOR PROTECTION: Fetch and verify ownership
    // ============================================
    const search = await SavedSearch.findById(id);

    if (!search) {
      return res.status(404).json({ success: false, message: "Saved search not found" });
    }

    // Verify ownership - compare database record's user with authenticated user
    if (search.user.toString() !== userId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${userId} tried to delete search owned by ${search.user}`);
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    await SavedSearch.deleteOne({ _id: id });

    return res.json({ success: true, message: "Saved search deleted successfully" });
  } catch (err) {
    console.error("deleteSavedSearch error:", err);
    return res.status(500).json({ success: false, message: "Failed to delete saved search" });
  }
};

// Update saved search settings (with ownership verification)
export const updateSavedSearch = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { id } = req.params;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid saved search ID" });
    }

    // ============================================
    // IDOR PROTECTION: Verify ownership
    // ============================================
    const search = await SavedSearch.findById(id);

    if (!search) {
      return res.status(404).json({ success: false, message: "Saved search not found" });
    }

    if (search.user.toString() !== userId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${userId} tried to update search owned by ${search.user}`);
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    // Sanitize update data
    const sanitizedData = sanitizeSavedSearchData(req.body);

    // Apply updates (only allowed fields)
    if (sanitizedData.name) {
      search.name = String(sanitizedData.name).substring(0, 100);
    }
    if (sanitizedData.notifyEmail !== undefined) {
      search.notifyEmail = Boolean(sanitizedData.notifyEmail);
    }
    if (sanitizedData.notifyInApp !== undefined) {
      search.notifyInApp = Boolean(sanitizedData.notifyInApp);
    }

    await search.save();

    return res.json({ success: true, savedSearch: search });
  } catch (err) {
    console.error("updateSavedSearch error:", err);
    return res.status(500).json({ success: false, message: "Failed to update saved search" });
  }
};
