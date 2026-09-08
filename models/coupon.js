const mongoose = require('mongoose');

const couponSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true
  },
  discountType: {
    type: String,
    enum: ['percent', 'fixed'],
    default: 'percent'
  },
  discountValue: {
    type: Number,
    required: true,
    min: 0
  },
  minOrderAmount: {
    type: Number,
    default: 0
  },
  expirationDate: {
    type: Date,
    default: null
  },
  active: {
    type: Boolean,
    default: true
  },
  usageCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

couponSchema.methods.isValid = function(cartTotal = 0) {
  if (!this.active) return false;
  if (this.expirationDate && new Date() > this.expirationDate) return false;
  if (cartTotal < this.minOrderAmount) return false;
  return true;
};

module.exports = mongoose.model('Coupon', couponSchema);
