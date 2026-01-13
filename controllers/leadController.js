import Lead from "../models/Lead.js";
import Property from "../models/Property.js";
import User from "../models/userModel.js";
import mongoose from "mongoose";
import { sendNewLeadNotification } from "../utils/emailService.js";

// ============================================
// SECURITY: Allowed status values for leads
// ============================================
const VALID_LEAD_STATUSES = ['new', 'contacted', 'interested', 'negotiating', 'converted', 'lost'];

/**
 * Sanitize and validate lead status
 */
const sanitizeLeadStatus = (status) => {
  if (!status || typeof status !== 'string') return null;
  const normalized = status.toLowerCase().trim();
  return VALID_LEAD_STATUSES.includes(normalized) ? normalized : null;
};

// Create a new lead when user expresses interest
export const createLead = async (userId, propertyId, userDetails) => {
  try {
    // Get property details with owner info
    const property = await Property.findById(propertyId).populate("owner", "name email");
    if (!property) {
      throw new Error("Property not found");
    }

    // Check if lead already exists
    const existingLead = await Lead.findOne({ user: userId, property: propertyId });
    if (existingLead) {
      return existingLead;
    }

    // Create lead with snapshots
    const lead = await Lead.create({
      property: propertyId,
      propertyOwner: property.owner._id || property.owner,
      user: userId,
      userSnapshot: {
        name: userDetails.name,
        email: userDetails.email,
        phone: userDetails.phone || "",
        profileImage: userDetails.profileImage || ""
      },
      propertySnapshot: {
        title: property.title,
        price: property.price || property.expectedPrice,
        listingType: property.listingType,
        city: property.city || property.address?.city,
        locality: property.locality || property.address?.area,
        propertyType: property.propertyTypeName || property.propertyType?.name,
        bhk: property.bhk || property.bhkType
      },
      status: "new",
      source: "website"
    });

    // Send email notification to property owner
    if (property.owner && property.owner.email) {
      const ownerName = property.owner.name || "Property Owner";
      const ownerEmail = property.owner.email;

      const leadData = {
        name: userDetails.name,
        email: userDetails.email,
        phone: userDetails.phone || ""
      };

      const propertyData = {
        title: property.title,
        price: property.price || property.expectedPrice,
        listingType: property.listingType,
        city: property.city || property.address?.city,
        locality: property.locality || property.address?.area,
        propertyType: property.propertyTypeName,
        bhk: property.bhk
      };

      // Send email asynchronously (don't await to avoid blocking)
      sendNewLeadNotification(ownerEmail, ownerName, leadData, propertyData)
        .then(result => {
          if (result.success) {
            console.log(`📧 Lead notification email sent to ${ownerEmail}`);
          }
        })
        .catch(err => console.error("Email send error:", err));
    }

    return lead;
  } catch (error) {
    console.error("Error creating lead:", error);
    throw error;
  }
};

// // Get all leads for a property owner
// export const getOwnerLeads = async (req, res) => {
//   try {
//     const ownerId = req.user._id;
//     const { status, property, page = 1, limit = 20, sort = "-createdAt" } = req.query;

//     // Build query
//     const query = { propertyOwner: ownerId };

//     if (status && status !== "all") {
//       query.status = status;
//     }

//     if (property && mongoose.Types.ObjectId.isValid(property)) {
//       query.property = property;
//     }

//     // Execute query with pagination
//     const skip = (parseInt(page) - 1) * parseInt(limit);

//     const [leads, total] = await Promise.all([
//       Lead.find(query)
//         .populate("user", "name email phone profileImage")
//         .populate("property", "title price listingType city locality images categorizedImages")
//         .sort(sort)
//         .skip(skip)
//         .limit(parseInt(limit)),
//       Lead.countDocuments(query)
//     ]);

//     // Get stats
//     const stats = await Lead.aggregate([
//       { $match: { propertyOwner: new mongoose.Types.ObjectId(ownerId) } },
//       {
//         $group: {
//           _id: "$status",
//           count: { $sum: 1 }
//         }
//       }
//     ]);

//     const statusStats = {
//       new: 0,
//       contacted: 0,
//       interested: 0,
//       negotiating: 0,
//       converted: 0,
//       lost: 0,
//       total: 0
//     };

//     stats.forEach(s => {
//       statusStats[s._id] = s.count;
//       statusStats.total += s.count;
//     });

//     res.status(200).json({
//       success: true,
//       data: leads,
//       stats: statusStats,
//       pagination: {
//         page: parseInt(page),
//         limit: parseInt(limit),
//         total,
//         pages: Math.ceil(total / parseInt(limit))
//       }
//     });
//   } catch (error) {
//     console.error("Error fetching leads:", error);
//     res.status(500).json({ success: false, message: 'An unexpected error occurred' });
//   }
// };

// Get leads for a specific property
export const getPropertyLeads = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const propertyId = req.params.propertyId;

    // Verify property belongs to user
    const property = await Property.findById(propertyId);
    if (!property || property.owner.toString() !== ownerId.toString()) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const leads = await Lead.find({ property: propertyId })
      .populate("user", "name email phone profileImage")
      .sort("-createdAt");

    res.status(200).json({ success: true, data: leads });
  } catch (error) {
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// Update lead status (with IDOR protection)
export const updateLeadStatus = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const leadId = req.params.id;
    const { status, notes } = req.body;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(leadId)) {
      return res.status(400).json({ success: false, message: 'Invalid lead ID' });
    }

    // ============================================
    // IDOR PROTECTION: Fetch lead and verify ownership
    // ============================================
    const lead = await Lead.findById(leadId);

    if (!lead) {
      return res.status(404).json({ success: false, message: 'Lead not found' });
    }

    // Verify ownership - compare database record's propertyOwner with authenticated user
    if (lead.propertyOwner.toString() !== ownerId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${ownerId} tried to update lead owned by ${lead.propertyOwner}`);
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    // Sanitize and validate status
    const updates = {};
    if (status) {
      const sanitizedStatus = sanitizeLeadStatus(status);
      if (!sanitizedStatus) {
        return res.status(400).json({ success: false, message: 'Invalid lead status' });
      }
      updates.status = sanitizedStatus;
    }

    // Sanitize notes
    if (notes !== undefined) {
      updates.notes = String(notes).substring(0, 2000); // Limit notes length
    }

    const updatedLead = await Lead.findByIdAndUpdate(
      leadId,
      { $set: updates },
      { new: true }
    ).populate('user', 'name email phone profileImage');

    res.status(200).json({ success: true, data: updatedLead });
  } catch (error) {
    console.error('Error updating lead status:', error);
    res.status(500).json({ success: false, message: 'An error occurred while updating the lead' });
  }
};

// Mark lead as viewed (with IDOR protection)
export const markLeadViewed = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const leadId = req.params.id;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(leadId)) {
      return res.status(400).json({ success: false, message: 'Invalid lead ID' });
    }

    // ============================================
    // IDOR PROTECTION: Fetch lead and verify ownership
    // ============================================
    const lead = await Lead.findById(leadId);

    if (!lead) {
      return res.status(404).json({ success: false, message: 'Lead not found' });
    }

    // Verify ownership from database record
    if (lead.propertyOwner.toString() !== ownerId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${ownerId} tried to mark lead owned by ${lead.propertyOwner} as viewed`);
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    await Lead.findByIdAndUpdate(leadId, {
      isViewed: true,
      viewedAt: new Date()
    });

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error marking lead as viewed:', error);
    res.status(500).json({ success: false, message: 'An error occurred' });
  }
};

// Add contact history entry (with IDOR protection and sanitization)
export const addContactHistory = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const leadId = req.params.id;
    const { action, note } = req.body;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(leadId)) {
      return res.status(400).json({ success: false, message: 'Invalid lead ID' });
    }

    // Validate required fields
    if (!action || typeof action !== 'string' || action.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'Action is required' });
    }

    // ============================================
    // IDOR PROTECTION: Fetch lead and verify ownership
    // ============================================
    const lead = await Lead.findById(leadId);

    if (!lead) {
      return res.status(404).json({ success: false, message: 'Lead not found' });
    }

    // Verify ownership from database record
    if (lead.propertyOwner.toString() !== ownerId.toString()) {
      console.warn(`⚠️ IDOR attempt: User ${ownerId} tried to add history to lead owned by ${lead.propertyOwner}`);
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    // Sanitize inputs
    const sanitizedAction = String(action).substring(0, 100);
    const sanitizedNote = note ? String(note).substring(0, 1000) : '';

    const updatedLead = await Lead.findByIdAndUpdate(
      leadId,
      {
        $push: {
          contactHistory: {
            action: sanitizedAction,
            note: sanitizedNote,
            date: new Date()
          }
        },
        $set: { status: 'contacted' }
      },
      { new: true }
    ).populate('user', 'name email phone profileImage');

    res.status(200).json({ success: true, data: updatedLead });
  } catch (error) {
    console.error('Error adding contact history:', error);
    res.status(500).json({ success: false, message: 'An error occurred' });
  }
};

// Get lead analytics/stats for dashboard
export const getLeadAnalytics = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const { days = 30 } = req.query;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Get leads by status
    const statusStats = await Lead.aggregate([
      { $match: { propertyOwner: new mongoose.Types.ObjectId(ownerId) } },
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 }
        }
      }
    ]);

    // Get leads by day for the chart
    const dailyLeads = await Lead.aggregate([
      {
        $match: {
          propertyOwner: new mongoose.Types.ObjectId(ownerId),
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Get leads by property
    const leadsByProperty = await Lead.aggregate([
      { $match: { propertyOwner: new mongoose.Types.ObjectId(ownerId) } },
      {
        $group: {
          _id: "$property",
          count: { $sum: 1 },
          propertyTitle: { $first: "$propertySnapshot.title" }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Get conversion rate
    const totalLeads = await Lead.countDocuments({ propertyOwner: ownerId });
    const convertedLeads = await Lead.countDocuments({ propertyOwner: ownerId, status: "converted" });
    const conversionRate = totalLeads > 0 ? ((convertedLeads / totalLeads) * 100).toFixed(1) : 0;

    // New leads in last 7 days
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const newLeadsThisWeek = await Lead.countDocuments({
      propertyOwner: ownerId,
      createdAt: { $gte: weekAgo }
    });

    // Unread leads count
    const unreadLeads = await Lead.countDocuments({
      propertyOwner: ownerId,
      isViewed: false
    });

    res.status(200).json({
      success: true,
      data: {
        statusStats: statusStats.reduce((acc, s) => {
          acc[s._id] = s.count;
          return acc;
        }, {}),
        dailyLeads,
        leadsByProperty,
        totalLeads,
        convertedLeads,
        conversionRate: parseFloat(conversionRate),
        newLeadsThisWeek,
        unreadLeads
      }
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// Helper function to get start and end of a day in UTC
export const getTodayDateRange = () => {
  const now = new Date();
  // Start of today (00:00:00.000Z)
  const startOfToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
  // Start of tomorrow (00:00:00.000Z)
  const startOfTomorrow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0));
  return { startOfToday, startOfTomorrow };
};

export const getOwnerLeads = async (req, res) => {
  try {
    const ownerId = req.user._id;
    const { status, property, page = 1, limit = 20, sort = "-createdAt", startDate, endDate } = req.query;

    const query = { propertyOwner: ownerId };

    if (status && status !== "all") query.status = status;
    if (property && mongoose.Types.ObjectId.isValid(property)) query.property = property;

    // Date Filtering Logic
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) {
        const start = new Date(startDate);
        start.setUTCHours(0, 0, 0, 0);
        query.createdAt.$gte = start;
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setUTCHours(23, 59, 59, 999);
        query.createdAt.$lte = end;
      }
    }

    // Stats Calculation
    const statsResult = await Lead.aggregate([
      { $match: { propertyOwner: new mongoose.Types.ObjectId(ownerId) } },
      { $group: { _id: "$status", count: { $sum: 1 } } }
    ]);

    const statusStats = { new: 0, contacted: 0, interested: 0, negotiating: 0, converted: 0, lost: 0, total: 0, today: 0 };

    statsResult.forEach(s => {
      statusStats[s._id] = s.count;
      statusStats.total += s.count;
    });

    // Today's Leads count
    const { startOfToday, startOfTomorrow } = getTodayDateRange();
    const todayCount = await Lead.countDocuments({
      propertyOwner: ownerId,
      createdAt: { $gte: startOfToday, $lt: startOfTomorrow },
    });
    statusStats.today = todayCount;

    // Execute query with pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [leads, total] = await Promise.all([
      Lead.find(query)
        .populate("user", "name email phone profileImage")
        .populate("property", "title price listingType city locality images categorizedImages")
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit)),
      Lead.countDocuments(query)
    ]);

    res.status(200).json({
      success: true,
      data: leads,
      stats: statusStats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error("Error fetching leads:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

// ... (getPropertyLeads, updateLeadStatus, markLeadViewed, addContactHistory, getLeadAnalytics - ensure getLeadAnalytics logic exists)


export const getAllLeads = async (req, res) => {
  try {
    const { page = 1, limit = 15, status, search, startDate, endDate } = req.query;
    const pageNumber = parseInt(page);
    const limitNumber = parseInt(limit);

    // 1. Build Query Filters
    let matchQuery = {};

    // Status Filter
    if (status && status !== 'all') {
      matchQuery.status = status;
    }

    // Search Filter (by user name, email, or property title)
    if (search) {
      // NOTE: For performance on large datasets, consider an index on:
      // { 'userSnapshot.name': 1, 'userSnapshot.email': 1, 'propertySnapshot.title': 1 }
      const searchRegex = new RegExp(search, 'i');
      matchQuery.$or = [
        { 'userSnapshot.name': searchRegex },
        { 'userSnapshot.email': searchRegex },
        { 'propertySnapshot.title': searchRegex },
      ];
    }

    // Date Range Filter
    let dateQuery = {};
    if (startDate) {
      // Start of the day for the startDate (00:00:00.000Z)
      const start = new Date(startDate);
      start.setUTCHours(0, 0, 0, 0); // Ensure it's the start of the day in UTC
      dateQuery.$gte = start;
    }
    if (endDate) {
      // End of the day for the endDate (23:59:59.999Z)
      const end = new Date(endDate);
      end.setUTCHours(23, 59, 59, 999); // Ensure it's the end of the day in UTC
      dateQuery.$lte = end;
    }

    if (startDate || endDate) {
      matchQuery.createdAt = dateQuery;
    }

    // --- Stats Calculation ---
    // Status aggregation for ALL leads (ignoring date/search filters for the main stats cards)
    const allLeads = await Lead.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    const stats = {
      total: 0,
      today: 0,
      new: 0,
      contacted: 0,
      interested: 0,
      negotiating: 0,
      converted: 0,
      lost: 0,
    };

    allLeads.forEach(item => {
      stats.total += item.count;
      if (stats[item._id] !== undefined) {
        stats[item._id] = item.count;
      }
    });

    // 2. Calculate Today's Leads Stat
    const { startOfToday, startOfTomorrow } = getTodayDateRange();

    const todayCount = await Lead.countDocuments({
      createdAt: {
        $gte: startOfToday,
        $lt: startOfTomorrow,
      },
    });
    stats.today = todayCount;


    // --- Leads Fetching (with filters and pagination) ---

    const totalLeadsInFilter = await Lead.countDocuments(matchQuery);

    // Fetch leads with necessary population for the Admin view
    const leads = await Lead.find(matchQuery)
      .populate("user", "name email phone profileImage")
      .populate("property", "title price listingType city locality images categorizedImages")
      .populate("propertyOwner", "name email phone profileImage") // Crucial for Admin view
      .sort({ createdAt: -1 }) // Sort by latest first
      .skip((pageNumber - 1) * limitNumber)
      .limit(limitNumber);

    const pagination = {
      page: pageNumber,
      pages: Math.ceil(totalLeadsInFilter / limitNumber),
      limit: limitNumber,
      total: totalLeadsInFilter,
    };

    res.status(200).json({
      success: true,
      data: leads,
      stats,
      pagination,
    });

  } catch (error) {
    console.error('Error fetching leads:', error);
    res.status(500).json({ success: false, message: 'Server error fetching leads.' });
  }
};

// ... other imports
import ExcelJS from 'exceljs';

// ... (other controller functions: createLead, getOwnerLeads, etc. remain unchanged)

// EXPORT FUNCTION
export const exportLeadsToExcel = async (req, res) => {
  try {
    const ownerId = req.user._id;

    // 1. Calculate Date Range (Default: Last 3 Months)
    const endDate = new Date(); // Now
    const startDate = new Date();
    startDate.setMonth(endDate.getMonth() - 3); // 3 months ago

    // Ensure we capture the full day for end date
    endDate.setUTCHours(23, 59, 59, 999);
    startDate.setUTCHours(0, 0, 0, 0);

    // 2. Fetch Leads
    const query = {
      propertyOwner: ownerId,
      createdAt: {
        $gte: startDate,
        $lte: endDate
      }
    };

    const leads = await Lead.find(query)
      .populate("user", "name email phone") // Only need basic fields
      .populate("property", "title locality city")
      .sort({ createdAt: -1 })
      .lean();

    if (!leads || leads.length === 0) {
      return res.status(404).json({ success: false, message: "No leads found for the last 3 months." });
    }

    // 3. Create Workbook
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Leads Data');

    // 4. Define Columns
    worksheet.columns = [
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Lead Name', key: 'name', width: 25 },
      { header: 'Email', key: 'email', width: 30 },
      { header: 'Phone', key: 'phone', width: 20 },
      { header: 'Property Title', key: 'property', width: 40 },
      { header: 'Location', key: 'location', width: 30 },
      { header: 'Status', key: 'status', width: 15 },
    ];

    // 5. Add Rows
    leads.forEach(lead => {
      worksheet.addRow({
        date: lead.createdAt ? new Date(lead.createdAt).toLocaleDateString('en-IN') : 'N/A',
        name: lead.userSnapshot?.name || lead.user?.name || 'N/A',
        email: lead.userSnapshot?.email || lead.user?.email || 'N/A',
        phone: lead.userSnapshot?.phone || lead.user?.phone || 'N/A',
        property: lead.propertySnapshot?.title || lead.property?.title || 'N/A',
        location: lead.propertySnapshot
          ? `${lead.propertySnapshot.locality}, ${lead.propertySnapshot.city}`
          : lead.property
            ? `${lead.property.locality}, ${lead.property.city}`
            : 'N/A',
        status: lead.status || 'new',
      });
    });

    // 6. Style Header (Optional but nice)
    worksheet.getRow(1).font = { bold: true };

    // 7. Set Response Headers
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=" + "Leads_History_3Months.xlsx"
    );

    // 8. Write to Response
    await workbook.xlsx.write(res);
    res.status(200).end();

  } catch (error) {
    console.error('Error exporting leads to Excel:', error);
    // Important: If headers are already sent, don't try to send JSON
    if (!res.headersSent) {
      res.status(500).json({ success: false, message: 'An unexpected error occurred' || 'Server error during export.' });
    }
  }
};
