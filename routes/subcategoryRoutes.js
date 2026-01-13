import express from "express";
import { createSubCategory, getSubCategories, deleteSubCategory, updateSubCategory, getSubCategoriesByCategory } from "../controllers/subcategoryController.js";
import { protectAdmin } from "../middleware/authAdmin.js";

const router = express.Router();

// ✅ Base route: /api/subcategories
router.post("/add", protectAdmin, createSubCategory);        // POST /api/subcategories/add
router.get("/list", getSubCategories);                       // GET  /api/subcategories/list
router.delete("/delete/:id", protectAdmin, deleteSubCategory);  // DELETE /api/subcategories/delete/:id
router.put("/edit/:id", protectAdmin, updateSubCategory);
// ✅ 🔹 Add this route for subcategories by category ID

router.get("/byCategory/:categoryId", getSubCategoriesByCategory);

export default router;
