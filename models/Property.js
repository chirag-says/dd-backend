import mongoose from "mongoose";

const propertySchema = new mongoose.Schema(
  {
    // Owner reference
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    propertyType: { type: mongoose.Schema.Types.ObjectId, ref: "PropertyType" },
    propertyTypeName: { type: String }, // Stores exact property type name like "Apartment / Flat", "Office Space"
    category: { type: mongoose.Schema.Types.ObjectId, ref: "Category" },
    categoryName: { type: String }, // Stores "Residential" or "Commercial"
    subcategory: { type: mongoose.Schema.Types.ObjectId, ref: "SubCategory" },

    title: { type: String, required: true },
    description: String,

    videoUrl: String,

    price: Number,
    priceUnit: { type: String, default: "Lac" },
    negotiable: { type: Boolean, default: false },
    gstApplicable: { type: String },

    bookingAmount: Number,

    area: {
      totalSqft: Number,
      carpetSqft: Number,
      builtUpSqft: Number,
      superBuiltUpSqft: Number,
      plotSqft: Number,
      pricePerSqft: Number,
    },

    amenities: [String],
    parking: {
      covered: { type: mongoose.Schema.Types.Mixed }, // Can be String or Number
      open: { type: mongoose.Schema.Types.Mixed },    // Can be String or Number
    },

    address: {
      line: String,
      area: String,
      city: String,
      state: String,
      pincode: String,
      landmark: String,
      nearby: [String],
      latitude: Number,
      longitude: Number,
    },

    // Convenience fields (duplicated from address for easier access)
    city: String,
    locality: String,

    // Regular images array (for backward compatibility)
    images: [String],
    rejectionReason: { type: String, default: "" },
    // Categorized images - stores images by room/area type
    categorizedImages: {
      // Residential categories
      residential: {
        exterior: [String],
        livingRoom: [String],
        bedroom: [String],
        bathroom: [String],
        kitchen: [String],
        balcony: [String],
        hall: [String],
        diningArea: [String],
        studyRoom: [String],
        poojaRoom: [String],
        garden: [String],
        parking: [String],
        floorPlan: [String],
        other: [String]
      },
      // Commercial categories
      commercial: {
        facade: [String],
        reception: [String],
        workArea: [String],
        cabin: [String],
        conferenceRoom: [String],
        pantry: [String],
        washroom: [String],
        warehouse: [String],
        loadingArea: [String],
        shopFloor: [String],
        displayArea: [String],
        seatingArea: [String],
        kitchenCommercial: [String],
        storageArea: [String],
        parking: [String],
        floorPlan: [String],
        other: [String]
      }
    },

    isApproved: { type: Boolean, default: true },

    // Property Status & Analytics
    status: { type: String, enum: ["active", "pending", "sold", "rented", "inactive"], default: "active" },
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    inquiries: { type: Number, default: 0 },

    // Track users who expressed interest
    interestedUsers: [{
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      interestedAt: { type: Date, default: Date.now }
    }],

    // Listing Details
    listingType: { type: String, enum: ["Rent", "Sell", "Sale", "rent", "sell", "sale"], default: "Rent" },
    availableFrom: Date,
    deposit: mongoose.Schema.Types.Mixed, // Security deposit / booking amount

    // Residential Fields
    bhk: String,
    bedrooms: Number,
    bathrooms: Number,
    balconies: Number,
    furnishing: String,
    floorNo: String,
    totalFloors: String,
    facing: String,
    constructionStatus: String,
    propertyAge: String,
    ageOfProperty: String,
    allowedFor: String,
    petFriendly: String,

    extras: {
      servantRoom: Boolean,
      poojaRoom: Boolean,
      studyRoom: Boolean,
      storeRoom: Boolean
    },

    // Commercial Fields
    commercialSubType: String,
    washrooms: Number,
    loadingArea: String,
    dockAvailable: Boolean,
    shutters: String,
    floorHeight: String,
    powerLoad: String,
    maintenance: mongoose.Schema.Types.Mixed, // Can be Number or "Included"
    maintenanceIncluded: Boolean,
    securityDeposit: Number,

    // Commercial Config Fields (Flattened)
    workstations: String,
    conferenceRooms: String,
    cabins: String,
    pantry: String,
    frontage: String,
    storage: String,
    displayWindows: String,
    displayArea: String,
    seatingCapacity: String,
    kitchenArea: String,
    barArea: String,
    outdoorSeating: String,
    meetingRooms: String,
    privateCabins: String,
    phoneBooths: String,
    loungeArea: String,
    loadingDocks: String,
    ceilingHeight: String,
    floorLoadCapacity: String,
    powerConnection: String,
    overheadCrane: String,
    centralAC: String,
    powerBackup: String,

    // Legal
    legal: {
      reraId: String,
      occupancyCertificate: Boolean,
      tradeLicense: Boolean,
      fireNoc: Boolean
    }
  },
  { timestamps: true }
);

export default mongoose.model("Property", propertySchema);