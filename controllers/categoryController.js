// controllers/categoryController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import Category from "../models/Category.js";

export const createCategory = async (req, res) => {
  try {
    const exists = await Category.findOne({
      name: req.body.name,
      propertyType: req.body.propertyType,
    });

    if (exists)
      return res.status(400).json({ success: false, message: "Category already exists" });

    const category = await Category.create(req.body);
    res.status(201).json({ success: true, data: category });
  } catch (err) {
    console.error('[Category] Create error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to create category' });
  }
};

export const getCategories = async (req, res) => {
  try {
    const list = await Category.find().populate("propertyType");
    res.json({ success: true, data: list });
  } catch (err) {
    console.error('[Category] Get all error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch categories' });
  }
};

export const deleteCategory = async (req, res) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) return res.status(404).json({ success: false, message: "Category not found" });
    res.json({ success: true, message: "Category deleted successfully" });
  } catch (err) {
    console.error('[Category] Delete error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete category' });
  }
};

export const updateCategory = async (req, res) => {
  try {
    const updated = await Category.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ success: false, message: "Category not found" });
    res.json({ success: true, data: updated });
  } catch (err) {
    console.error('[Category] Update error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update category' });
  }
};
