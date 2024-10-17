import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema({
  userName: {
    type: String,
    minLength: [3, "Le nom d'utilisateur doit contenir au moins 3 caractères."],
    maxLength: [40, "Le nom d'utilisateur ne peut pas dépasser 40 caractères."],
  },
  password: {
    type: String,
    select: false,
    minLength: [8, "Le mot de passe doit contenir au moins 8 caractères."],
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  address: String,
  phone: {
    type: String,
    minLength: [
      10,
      "Le numéro de téléphone doit contenir exactement 10 chiffres.",
    ],
    maxLength: [
      10,
      "Le numéro de téléphone doit contenir exactement 10 chiffres.",
    ],
  },
  profileImage: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  paymentMethods: {
    bankTransfer: {
      bankAccountNumber: String, // Numéro de compte bancaire
      bankAccountName: String, // Nom du titulaire du compte
      bankName: String, // Nom de la banque
    },
    mobilePayment: {
      mobileAccountNumber: String, // Numéro de compte mobile
    },
    cashOnDelivery: {
      available: {
        type: Boolean,
        default: true,
      },
    },
  },
  role: {
    type: String,
    enum: ["Auctioneer", "Bidder", "Super Admin"],
    default: "Bidder", // Default role
  },
  unpaidCommission: {
    type: Number,
    default: 0,
  },
  auctionsWon: {
    type: Number,
    default: 0,
  },
  moneySpent: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bcrypt.hash(this.password, 10);
});

// Compare passwords
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate JSON Web Token
userSchema.methods.generateJsonWebToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

export const User = mongoose.model("User", userSchema);
