// models/product.js
const mongoose = require('mongoose');

// models/product.js - Update the type field
const producthomeSchema = new mongoose.Schema({
  title: String,
  price: Number,
  buyPrice: {
    type: Number,
    default: 0
  },
  oldPrice: {          
    type: Number,
    default: null
  },
  disponible: {
    type: Boolean,
    default: true
  },
  stock: {
    type: Number,
    default: 10
  },
  image: [String],         
  description: String,     
  details: Object,         
  // 👇 MAKE TYPE MORE STRUCTURED
  type: {
    type: String,
    index: true,  // Add index for faster queries
    lowercase: true,  // Convert to lowercase for consistency
    trim: true  // Remove extra spaces
  },
  videoId: String,
  videoFile: {
    type: String,
    default: null
  },
  stlFile: {
    type: String,
    default: null
  },
  model3D: {
    enabled: {
      type: Boolean,
      default: false
    },
    autoRotate: {
      type: Boolean,
      default: true
    },
    defaultColor: {
      type: String
    }
  },
  // Links a lighting product (type: "lighting") to the vase it's built on top of,
  // so the vase page can offer "also available as a lamp" and vice versa. Left
  // null for vases themselves and for standalone lighting products with no vase base.
  baseVaseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Producthome',
    default: null
  }
  // ❌ REMOVE relatedProducts array - we don't need it!
}, {
  timestamps: true
});
// Virtual property to check if product has 3D model
producthomeSchema.virtual('has3DModel').get(function() {
  return !!this.stlFile;
});

// Virtual property to check if product has video
producthomeSchema.virtual('hasVideo').get(function() {
  return !!(this.videoFile || this.videoId);
});

module.exports = mongoose.model('Producthome', producthomeSchema);
