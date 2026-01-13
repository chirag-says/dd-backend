import express from "express";
import { createCategory, getCategories, deleteCategory, updateCategory } from "../controllers/categoryController.js";
import { protectAdmin } from "../middleware/authAdmin.js";

const router = express.Router();

// ✅ Base route: /api/categories
router.post("/add-category", protectAdmin, createCategory);     // POST /api/categories/add
router.get("/list-category", getCategories);                    // GET  /api/categories/list
router.delete("/delete/:id", protectAdmin, deleteCategory);  // DELETE /api/categories/delete/:id
router.put("/edit/:id", protectAdmin, updateCategory);
export default router;