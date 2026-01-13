// controllers/subcategoryController.js
// SECURITY FIX: Sanitized error responses to prevent information disclosure
import SubCategory from "../models/SubCategory.js";

export const createSubCategory = async (req, res) => {
  try {
    const exists = await SubCategory.findOne({
      name: req.body.name,
      category: req.body.category,
    });

    if (exists)
      return res.status(400).json({ success: false, message: "Subcategory exists" });

    const sub = await SubCategory.create(req.body);
    res.status(201).json({ success: true, data: sub });
  } catch (err) {
    console.error('[SubCategory] Create error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to create subcategory' });
  }
};

export const getSubCategories = async (req, res) => {
  try {
    const list = await SubCategory.find()
      .populate("category")
      .populate("propertyType");

    res.json({ success: true, data: list });
  } catch (err) {
    console.error('[SubCategory] Get all error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch subcategories' });
  }
};

export const getSubCategoriesByCategory = async (req, res) => {
  try {
    const subs = await SubCategory.find({
      category: req.params.categoryId,
    });

    res.json({ success: true, data: subs });
  } catch (err) {
    console.error('[SubCategory] Get by category error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch subcategories' });
  }
};

export const deleteSubCategory = async (req, res) => {
  try {
    const subcategory = await SubCategory.findByIdAndDelete(req.params.id);
    if (!subcategory) return res.status(404).json({ success: false, message: "Subcategory not found" });
    res.json({ success: true, message: "Subcategory deleted" });
  } catch (err) {
    console.error('[SubCategory] Delete error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete subcategory' });
  }
};

export const updateSubCategory = async (req, res) => {
  try {
    const updated = await SubCategory.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ success: false, message: "Subcategory not found" });
    res.json({ success: true, data: updated });
  } catch (err) {
    console.error('[SubCategory] Update error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to update subcategory' });
  }
};
