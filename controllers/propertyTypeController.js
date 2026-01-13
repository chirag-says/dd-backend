// controllers/propertyTypeController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import PropertyType from "../models/PropertyType.js";

export const createPropertyType = async (req, res) => {
  try {
    const exists = await PropertyType.findOne({ name: req.body.name });
    if (exists) return res.status(400).json({ success: false, message: "Already exists" });

    const type = await PropertyType.create(req.body);
    res.status(201).json({ success: true, data: type });
  } catch (err) {
    console.error('[PropertyType] Create error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to create property type' });
  }
};

export const getPropertyTypes = async (req, res) => {
  try {
    const list = await PropertyType.find().sort({ createdAt: -1 });
    res.json({ success: true, data: list });
  } catch (err) {
    console.error('[PropertyType] Get all error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch property types' });
  }
};

export const deletePropertyType = async (req, res) => {
  try {
    const propertyType = await PropertyType.findByIdAndDelete(req.params.id);
    if (!propertyType) return res.status(404).json({ success: false, message: "Property type not found" });
    res.json({ success: true, message: "Property type deleted successfully" });
  } catch (err) {
    console.error('[PropertyType] Delete error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete property type' });
  }
};

export const updatePropertyType = async (req, res) => {
  try {
    const updated = await PropertyType.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ success: false, message: "Property type not found" });
    res.json({ success: true, data: updated });
  } catch (err) {
    console.error('[PropertyType] Update error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update property type' });
  }
};
