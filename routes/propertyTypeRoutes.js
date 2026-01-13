import express from "express";

import { protectAdmin } from "../middleware/authAdmin.js";
import { createPropertyType, getPropertyTypes, deletePropertyType, updatePropertyType } from '../controllers/propertyTypeController.js'
const router = express.Router();

router.post("/add-property-type", protectAdmin, createPropertyType);
router.get("/list-propertytype", getPropertyTypes);
router.delete("/delete/:id", protectAdmin, deletePropertyType);
router.put("/edit/:id", protectAdmin, updatePropertyType);

export default router;
