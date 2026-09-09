const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const Cart = require("../models/cart");
const getCleanUserData = require('../utils/userData');
const sendFacebookCAPIEvent = require('../services/metaCapi');
const { getBotClassification } = require('../utils/botDetection');
const nodemailer = require('nodemailer');
const axios = require('axios');
const User = require('../models/user');
const { createPayment, verifyPayment } = require('../helpers/chargily');
const { sendPurchaseForDeliveredCOD } = require('../helpers/deliveryEvents');
const { sendTelegramMessage } = require('../helpers/telegram');
require('dotenv').config();
const twilio = require('twilio');
const Notification = require('../models/notification');
const Producthome = require('../models/producthome');
const Paintello = require('../models/paintello');
const Coupon = require('../models/coupon');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const Order = require('../models/order');
const WhatsAppMessage = require('../models/whatsappMessage');
const Review = require('../models/review');
const middleware = require('../middleware');
const ReturnRequest = require('../models/ReturnRequest');
const { isLoggedIn } = require('../middleware/index');
const mongoose = require('mongoose');
const { sendAdminOrderEmail, sendClientReplyEmail, sendReturnConfirmationEmail } = require('../utils/mailer');
const Blue = require('../models/blue');
const Pink = require('../models/pink');
const Grey = require('../models/grey');
const Green = require('../models/green');
const Yelloow = require('../models/yelloow');
const Neutral = require('../models/neutral');
const passport = require('passport');
const header = require('../models/header');
const shipping = require('../models/shipping');
const Newsletter = require('../models/newsletter');
const Incoming = require('../models/Incoming');
const fs = require('fs');
const path = require('path');
const furniteur = require('../models/furniteur');
const { isBotRequest } = require('../utils/botDetection');
// ===== HELPERS - BOT SAFE & META COMPLIANT =====
function generateEventId() { return crypto.randomUUID(); }

function getEventSourceUrl(req) {
  const protocol = req.headers["x-forwarded-proto"] || req.protocol || "https";
  const host = (req.get("host") || "").split(":")[0];
  return `${protocol}://${host}${req.originalUrl}`;
}

function setFbcCookieIfNeeded(req, res, userData) {
  if (userData && userData._isNewFbc && userData.fbc) {
    res.cookie("_fbc", userData.fbc, {
      maxAge: 90 * 24 * 60 * 60 * 1000,
      httpOnly: false,
      secure: true,
      sameSite: "Lax",
      path: "/"
    });
  }
}

function getTestCode(req) {
  return req.query.test_event_code || req.session?.preGeneratedEventIds?.testCode || process.env.FB_TEST_EVENT_CODE || undefined;
}

// Valid Mongo ObjectId check - avoids CastError -> unwanted 500s on bad/scraped ids
function isValidObjectId(id) {
  return typeof id === 'string' && mongoose.Types.ObjectId.isValid(id);
}

// Timing-safe comparison for secrets passed in query strings (delivery link, webhook verify token)
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Basic Algerian mobile number validation (matches the pattern already used in /track-login)
function isValidAlgerianNumero(numero) {
  return typeof numero === 'string' && /^0[5-7][0-9]{8}$/.test(numero.trim());
}

// Clamps a raw ?qty= value to a sane positive range. Two purposes:
// - negative/zero/non-numeric input already falls back to 1 via `|| 1`, but a very
//   large value (e.g. ?qty=99999999) would otherwise drive `for(let i=0;i<quantity;i++)`
//   to loop tens of millions of times synchronously and block the whole event loop -
//   a trivial single-request DoS. This caps that.
const MAX_CART_QTY = 50;
function clampQuantity(raw) {
  const n = parseInt(raw) || 1;
  return Math.min(MAX_CART_QTY, Math.max(1, n));
}

// Escapes regex special characters before using free text (e.g. a product title word)
// inside a MongoDB $regex - otherwise a title containing ( ) + . * etc. produces an
// invalid regex and throws, crashing the whole page render.
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// `disponible` is meant to be a boolean stock flag, but depending on how a record was
// saved it may end up stored as something else (string "false", 0, ...) - a strict
// `disponible: true` query match would then silently exclude it. Treat anything in
// this "false-like" list as unavailable; everything else (including a missing field)
// as available. $nin also matches documents where the field doesn't exist at all.
// `disponible` is schema-typed as Boolean, and Mongoose casts query condition values
// against the schema type - so putting string variants like 'non' in a $nin against
// this field throws a CastError before the query even reaches MongoDB (Mongoose's
// Boolean caster only recognizes true/'true'/1/'1'/'yes' and false/'false'/0/'0'/'no').
// If a document was edited directly in the Atlas UI it can still end up with a raw
// string value despite the schema. Filtering in plain JS after a simple, safe fetch
// sidesteps Mongoose's query-side casting entirely while still catching those cases.
const UNAVAILABLE_VALUES = [false, 0, 'false', '0', 'no', 'non'];
function isAvailable(product) {
  if (!product) return false;
  if (typeof product.stock === 'number' && product.stock <= 0) return false;
  return !UNAVAILABLE_VALUES.includes(product.disponible);
}

// ===== BLOCK NOISE ROUTES - NO CAPI =====
router.head('/', (req, res) => res.status(200).end());
router.get('/health', (req, res) => res.status(200).send('ok'));
router.head('/health', (req, res) => res.status(200).end());
router.get(['/robots.txt','/ads.txt','/favicon.ico','/favicon/favicon-32x32.png'], (req,res) => res.status(404).end());

// ===== FACEBOOK AUTH - NO CAPI =====
router.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
router.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login', failureFlash: true }), (req,res) => res.redirect('/'));

// ===== PRIVACY & TERMS - FIXED =====
router.get('/privacy', async (req, res) => {
  try {
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req, res, userData);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:getTestCode(req) }).catch(()=>{});
      console.log("✅ Privacy PageView queued");
    } else {
      console.log("🤖 Bot detected – Privacy PageView skipped", getBotClassification(req)?.botType);
    }
    res.render('privacy', { title:'Politique de Confidentialité', req, metaEventIdPageView:eventIdPageView, user:req.user });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
});

router.get('/terms', async (req, res) => {
  try {
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req, res, userData);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:getTestCode(req) }).catch(()=>{});
      console.log("✅ Terms PageView queued");
    } else {
      console.log("🤖 Bot detected – Terms PageView skipped");
    }
    res.render('terms', { title:"Conditions Générales d'Utilisation", req, metaEventIdPageView:eventIdPageView, user:req.user });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
});

// ===== COLOR CATEGORY PAGES - FIXED =====
async function renderColorCategory(req, res, viewName, logName) {
  try {
    const headers = await header.find({}).lean();
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req, res, userData);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:getTestCode(req) }).catch(()=>{});
      console.log(`✅ ${logName} PageView queued`);
    } else {
      console.log(`🤖 Bot detected – ${logName} PageView skipped`);
    }
    res.render(viewName, { headers, req, metaEventIdPageView:eventIdPageView, user:req.user });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
}

router.get("/coulors/blue", (req,res) => renderColorCategory(req,res,"coulors/blue","Blue"));
router.get("/coulors/greens", (req,res) => renderColorCategory(req,res,"coulors/greens","Green"));
router.get("/coulors/grey", (req,res) => renderColorCategory(req,res,"coulors/grey","Grey"));
router.get("/coulors/yellowv2", (req,res) => renderColorCategory(req,res,"coulors/yellowv2","Yellow"));
router.get("/coulors/pink", (req,res) => renderColorCategory(req,res,"coulors/pink","Pink"));
router.get("/coulors/neutral", (req,res) => renderColorCategory(req,res,"coulors/neutral","Neutral"));

// ===== GENERIC PRODUCT PAGE HANDLER - FIXED FOR ALL COLORS =====
async function handleProductPage(req, res, Model, viewPath, logPrefix) {
  try {
    const rawId = req.params.id;
    const cleanId = rawId.replace(/\.\w+$/, '');
    if (!isValidObjectId(cleanId)) return res.status(404).send("Product not found");
    const product = await Model.findById(cleanId).lean();
    if (!product) return res.status(404).send("Product not found");

    const eventIdPageView = generateEventId();
    const eventIdView = generateEventId();
    const eventIdCart = generateEventId();
    const eventIdCheckout = generateEventId();
    const userData = getCleanUserData(req);

    if (userData) {
      setFbcCookieIfNeeded(req, res, userData);
      const productIdStr = product._id.toString();
      const testCode = getTestCode(req);
      if (req.query.test_event_code) req.session.preGeneratedEventIds = { ...(req.session.preGeneratedEventIds||{}), testCode };

      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:testCode }).catch(()=>{});
      const productCategory = product.category || product.type || 'vases';
      sendFacebookCAPIEvent({ 
        eventName:"ViewContent", eventId:eventIdView, userData, 
        customData:{ content_name:product.title, content_category:productCategory, content_ids:[productIdStr], contents:[{id:productIdStr, quantity:1, item_price:Number(product.price)}], content_type:"product", value:Number(product.price), currency:"DZD" },
        eventSourceUrl:getEventSourceUrl(req), testEventCode:testCode
      }).catch(()=>{});
      console.log(`✅ ${logPrefix} PageView + ViewContent queued`);
    } else {
      console.log(`🤖 Bot detected – ${logPrefix} no CAPI`, getBotClassification(req)?.botType);
    }

    req.session.preGeneratedEventIds = { ...(req.session.preGeneratedEventIds||{}), cart:eventIdCart, checkout:eventIdCheckout, testCode:getTestCode(req) };

    res.render(viewPath, {
      [logPrefix.toLowerCase()]: product,
      blue: product, green: product, grey: product, yelloow: product, pink: product, neutral: product,
      req,
      metaEventIdView:eventIdView,
      metaEventIdCart:eventIdCart,
      metaEventIdCheckout:eventIdCheckout,
      metaEventIdPageView:eventIdPageView,
      user:req.user,
      login:req.isAuthenticated()
    });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
}

async function handleAddToCart(req, res, Model, logPrefix) {
  try {
    const rawId = req.params.id;
    const cleanId = rawId.replace(/\.\w+$/, '');
    if (!isValidObjectId(cleanId)) return res.status(404).send("Product not found");
    const quantity = clampQuantity(req.query.qty);
    const redirectTo = req.query.redirect;
    const cart = new Cart(req.session.cart || {});
    const product = await Model.findById(cleanId).lean();
    if (!product) return res.status(404).send("Product not found");

    for (let i=0;i<quantity;i++) cart.add(product, product._id.toString());
    req.session.cart = cart;

    const userData = getCleanUserData(req);
    if (!userData) {
      console.log(`🤖 Bot detected – ${logPrefix} AddToCart skipped`);
      return res.redirect(redirectTo==="checkout"?"/checkout":"/shop");
    }

    const eventIds = req.session.preGeneratedEventIds || {};
    const eventIdCart = eventIds.cart || generateEventId();
    const testCode = getTestCode(req);
    const productIdStr = product._id.toString();

    const productCategory = product.category || product.type || 'vases';
    await sendFacebookCAPIEvent({
      eventName:"AddToCart", eventId:eventIdCart, userData,
      customData:{ content_name:product.title, content_category:productCategory, content_ids:[productIdStr], contents:[{id:productIdStr, quantity, item_price:Number(product.price)}], content_type:"product", value:Number(product.price)*quantity, currency:"DZD" },
      eventSourceUrl:getEventSourceUrl(req), testEventCode:testCode
    });

    console.log(`✅ ${logPrefix} AddToCart sent`);
    if (req.session.preGeneratedEventIds) delete req.session.preGeneratedEventIds.cart;
    res.redirect(redirectTo==="checkout"?"/checkout":"/shop");
  } catch (error) { console.error(error); res.status(500).send("Server Error"); }
}

router.get("/blue/:id", (req,res) => handleProductPage(req,res,Blue,"event/blue","Blue"));
router.get("/add-to-cart-blue/:id", (req,res) => handleAddToCart(req,res,Blue,"Blue"));
router.get("/green/:id", (req,res) => handleProductPage(req,res,Green,"event/green","Green"));
router.get("/add-to-cart-green/:id", (req,res) => handleAddToCart(req,res,Green,"Green"));
router.get("/grey/:id", (req,res) => handleProductPage(req,res,Grey,"event/grey","Grey"));
router.get("/add-to-cart-grey/:id", (req,res) => handleAddToCart(req,res,Grey,"Grey"));
router.get("/yelloow/:id", (req,res) => handleProductPage(req,res,Yelloow,"event/yelloow","Yellow"));
router.get("/add-to-cart-yelloow/:id", (req,res) => handleAddToCart(req,res,Yelloow,"Yellow"));
router.get("/pink/:id", (req,res) => handleProductPage(req,res,Pink,"event/pink","Pink"));
router.get("/add-to-cart-pink/:id", (req,res) => handleAddToCart(req,res,Pink,"Pink"));
router.get("/neutral/:id", (req,res) => handleProductPage(req,res,Neutral,"event/neutral","Neutral"));
router.get("/add-to-cart-neutral/:id", (req,res) => handleAddToCart(req,res,Neutral,"Neutral"));

// ===== SHOP & HOME - FIXED =====
router.get("/shop", async (req, res) => {
  try {
    const cart = new Cart(req.session.cart || {});
    const shippings = await shipping.find({}).lean();
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req,res,userData);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:getTestCode(req) }).catch(()=>{});
      console.log("✅ Shop PageView queued");
    } else {
      console.log("🤖 Bot detected – Shop PageView skipped");
    }
    const metaEvent = req.session.metaEventData ? { id:req.session.metaEventId, ...req.session.metaEventData } : null;
    if (req.session.metaEventData) { delete req.session.metaEventId; delete req.session.metaEventData; }
    const products = cart.generateArray ? cart.generateArray() : [];
    res.render("event/shop", { metaEvent, cart, products, shippings, totalPrice:cart.totalPrice||0, totalQty:cart.totalQty||0, user:req.user||null, req, metaEventIdPageView:eventIdPageView });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
});

router.get("/", async (req, res) => {
 

  // DEBUG: see who hits /
  console.log(`HIT / UA=${req.headers['user-agent']?.slice(0,100)} IP=${req.headers['x-forwarded-for']?.split(',')[0]} MODE=${req.headers['sec-fetch-mode']}`);

  if (isBotRequest(req, { blockCloudIPs: true })) {
    return res.status(200).send('ok'); // block, don't render 21389
  }

  try {
    const successMsg = req.flash("success")[0];
    const errorMsg = req.flash("error")[0];
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req,res,userData);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:getTestCode(req) }).catch(()=>{});
      console.log("✅ Home PageView queued");
    } else {
      console.log("🤖 Bot detected – Home PageView skipped");
    }
    const headers = await header.find({}).lean();
    res.render("event/home", { headers, req, successMsg, errorMsg, metaEventIdPageView:eventIdPageView, user:req.user });
  } catch (err) { console.error(err); res.status(500).send("Error"); }
});

// ===== CART ACTIONS - NO CAPI =====
router.get('/reduce/:id', (req,res) => { const cart = new Cart(req.session.cart||{}); cart.reduceByOne(req.params.id); req.session.cart=cart; res.redirect('/shop'); });
router.get('/remove/:id', (req,res) => { const cart = new Cart(req.session.cart||{}); cart.removeItem(req.params.id); req.session.cart=cart; res.redirect('/shop'); });
router.post("/cart/increase/:id", async (req,res) => {
  try {
    const cart = new Cart(req.session.cart); const item = cart.items[req.params.id];
    if (item && item.isDiscounted) cart.addDiscounted(item.item, req.params.id, item.discountPercent||0.3);
    else cart.increaseQty(req.params.id);
    req.session.cart=cart;
    res.json({ success:true, qty:cart.items[req.params.id]?.qty||0, itemTotal:cart.items[req.params.id]?.price||0, totalPrice:cart.totalPrice, totalQty:cart.totalQty });
  } catch(e){ res.status(500).json({success:false}); }
});
router.post("/cart/remove/:id", async (req,res) => {
  try {
    const cart = new Cart(req.session.cart); const item = cart.items[req.params.id];
    if (item && !item.isDiscounted) {
      const hasDiscounted = Object.values(cart.items).some(c=>c.isDiscounted && c.discountedWith===req.params.id);
      if (hasDiscounted) return res.json({success:false, error:"Cannot remove main product while discounted item is in cart."});
    }
    cart.removeItem(req.params.id); req.session.cart=cart;
    res.json({success:true, totalPrice:cart.totalPrice, totalQty:cart.totalQty});
  } catch(e){ res.status(500).json({success:false}); }
});
router.post("/cart/decrease/:id", async (req,res) => {
  try {
    const cart = new Cart(req.session.cart);
    if (!cart.items[req.params.id]) return res.json({success:false});
    const item = cart.items[req.params.id];
    if (!item.isDiscounted && item.qty===1) {
      const hasDiscounted = Object.values(cart.items).some(c=>c.isDiscounted && c.discountedWith===req.params.id);
      if (hasDiscounted) return res.json({success:false, error:"Cannot remove main product while discounted item is in cart."});
    }
    cart.decreaseQty(req.params.id); req.session.cart=cart;
    res.json({success:true, qty:cart.items[req.params.id]?.qty||0, itemTotal:cart.items[req.params.id]?.price||0, totalPrice:cart.totalPrice, totalQty:cart.totalQty});
  } catch(e){ res.status(500).json({success:false}); }
});
router.post("/cart/remove-both", async (req,res) => {
  try { const cart = new Cart(req.session.cart); cart.removeItem(req.body.mainProductId); cart.removeItem(req.body.discountedProductId); req.session.cart=cart; res.json({success:true, totalPrice:cart.totalPrice, totalQty:cart.totalQty}); } catch(e){ res.status(500).json({success:false}); }
});

// ===== CHECKOUT - FIXED =====
// GET /checkout
router.get("/checkout", async (req, res) => {
  if (!req.session.cart) return res.redirect("/shop");
  const cart = new Cart(req.session.cart);
  const errMsg = req.flash("error")[0];

  let discountAmount = 0, totalBeforeDiscount = 0, hasDiscount = false;
  if (cart.items) {
    for (const id in cart.items) {
      const item = cart.items[id];
      const product = item.item || {};
      const fallbackUnitPrice = item.qty ? (item.price || 0) / item.qty : (product.price || 0);
      const orig = item.originalPrice || product.price || fallbackUnitPrice;
      if (item.isDiscounted) {
        hasDiscount = true;
        const disc = item.unitPrice || fallbackUnitPrice;
        discountAmount += (orig - disc) * item.qty;
      }
      totalBeforeDiscount += orig * item.qty;
    }
  }

  const eventIdPageView = generateEventId();
  const eventIdInitiateCheckout = generateEventId();
  const userData = getCleanUserData(req);
  const testCode = getTestCode(req);

  req.session.preGeneratedEventIds = {
    ...(req.session.preGeneratedEventIds || {}),
    initiateCheckout: eventIdInitiateCheckout,
    testCode: testCode
  };

  if (userData) {
    setFbcCookieIfNeeded(req, res, userData);
    sendFacebookCAPIEvent({
      eventName: "PageView",
      eventId: eventIdPageView,
      userData,
      eventSourceUrl: getEventSourceUrl(req),
      customData: {},
      testEventCode: testCode
    }).catch(()=>{});
  }

  res.render("event/checkout", {
    totalPrice: cart.totalPrice || 0,
    totalBeforeDiscount,
    discountAmount,
    hasDiscount,
    errMsg,
    noError: !errMsg,
    cart,
    metaEventIdPageView: eventIdPageView,
    metaEventIdInitiateCheckout: eventIdInitiateCheckout,
    user: req.user,
    req
  });
});

// wilayaShippingInfo object - KEEP YOUR EXISTING FULL OBJECT HERE
const wilayaShippingInfo = {
  "adrar": { fee: 800, delay: "4–6 jours", communes: ["Adrar","Reggane","Aoulef","Timimoun","Zaouiet Kounta","Fenoughil","Bouda","Tamentit","Sali","Tsabit","In Zghmir","Ouled Ahmed Timmi", "Akabli", "Bordj Badji Mokhtar", "Charouine", "Deldoul", "Metarfa", "Ouled Aissa", "Sebaa", "Talmin", "Tamest", "Tamantit", "Tinerkouk", "Zaouiet el Arab"] },
   "chlef": { fee: 500, delay: "2–4 jours", communes: ["Chlef","Ténès","Oued Fodda","El Karimia","Sidi Akkacha","Ouled Fares","Sendjas","El Marsa","Oued Goussine","Taougrit","Zeboudja","Benairia","Herenfa","Beni Haoua","Beni Rached","Sobha","Labiod Medjadja", "Abou El Hassane", "Aïn Merane", "Beni Bouateb", "Bougouffa", "Breira", "Chettia", "Dahra", "El Hadjadj", "Harchoun", "Moussadek", "Oued Sly", "Ouled Abbes", "Ouled Ben Abdelkader", "Sidi Abderrahmane", "Tadjena", "Talassa", "Tenes", "Zeghaia"] },
  "laghouat": { fee: 650, delay: "3–5 jours", communes: ["Laghouat","Aflou","Brida","Sidi Makhlouf","Ksar El Hirane","Gueltat Sidi Saad","El Assafia","Oued Morra","Tadjmout","El Ghicha","Hassi R'Mel","Sebgag","Ain Madhi", "Benacer Ben Chohra", "El Houaita", "Hadj Mechri", "Kheneg", "Oued M'Zi", "Sidi Bouzid", "Tadjemout", "Taouiala", "Touggourt", "Zelfana"] },
  "oum el bouaghi": { fee: 550, delay: "2–4 jours", communes: ["Oum El Bouaghi","Ain Beida","Ain M'Lila","Sigus","Ain Babouche","Behir Chergui","Fkirina","Ksar Sbahi","El Fedjoudj","Souk Naamane","El Belala","Ain Kercha", "Ain Diss", "Ain Fakroun", "Ain Zitoun", "Berriche", "Bir Chouhada", "Dhalaa", "El Amiria", "El Djazia", "El Harmilia", "Fkirina", "Hanchir Toumghani", "Meskiana", "Oued Nini", "Ouled Gacem", "Ouled Hamla", "Ouled Zouai", "Rahia", "Souk Naamane", "Zorg"] },
  "batna": { fee: 550, delay: "2–4 jours", communes: ["Batna","Timgad","Barika","Merouana","N Gaous","Arris","Ain Touta","Seriana","Chemora","Djerma","Fesdis","Ouled Fadel","Oued Chaaba","El Madher","Tazoult", "Ain Djasser", "Ain Yagout", "Arris", "Azil Abderrahmane", "Boulhilat", "Boumaguer", "Bouzina", "Chir", "Djezzar", "El Hassi", "Foum Toub", "Ghassira", "Gosbat", "Guigba", "Hidoussa", "Ichemoul", "Inoughissen", "Kimmel", "Lazrou", "M'doukel", "Menaa", "Oued El Ma", "Ouled Ammar", "Ouled Aouf", "Ouled Sellem", "Ouled Si Slimane", "Rahbat", "Ras El Aioun", "Sefiane", "Seggana", "Talkhamt", "Taxlent", "Teniet El Abed", "Tighanimine", "Tilatou", "Timgad", "Tkout", "Zanet El Beida"] },
  "bejaia": {
  fee: 500,
  delay: "2–3 jours",
  communes: [
    "Sidi Aïch","Aït-Smail","Akbou","Akfadou","Amalou", "Amizour","Barbacha","Chellata","Darguina","Draâ El-Kaïd","Leflaye","Feraoun","Ighram","Kendira","Kherrata","Melbou","Ouzellaguen","Seddouk","Souk Oufella","Sidi Ayad","Tamokra","Tamridjet","Taskriout","Tazmalt","Tibane","Tichy","Tifra","Toudja","Tizi N'Berber","Bouhamza","Boukhelifa","Aït Mellikeche","Beni Djellil","Beni Ksila","Beni Maouche","Ighil Ali","Fenaïa Ilmaten","Oued Ghir","Souk El Ténine","Taourirt Ighil","Tinebdar","Timezrit","Tala Hamza","Adekar","Boudjellil","Chemini","Aït R'zine","Aokas","Bejaia","El Kseur"
  ]
},
  "biskra": { fee: 600, delay: "3–5 jours", communes: ["Biskra","El Kantara","Sidi Okba","Tolga","Ouled Djellal","Mekhadma","Zeribet El Oued","Ourlal","Chetma","El Haouch","Doucen","Foughala","Branis", "Ain Naga", "Ain Zaatout", "Bordj Ben Azzouz", "Bouchagroune", "Chaiba", "Djemorah", "El Feidh", "El Hadjab", "El Outaya", "Khenguet Sidi Nadji", "Lioua", "M'Chouneche", "M'Lili", "Oumache", "Oum Laadham", "Sidi Khaled", "Tolga", "Zeribet el Oued"] },
  "bechar": { fee: 750, delay: "4–6 jours", communes: ["Bechar","Kenadsa","Beni Ounif","Taghit","Abadla","Ouled Khoudir","Erg Ferradj","Beni Abbes","Timoudi","Tamtert","Igli", "Boukais", "El Ouata", "Meridja", "Mogheul", "Tabelbala"] },
  "blida": { fee: 300, delay: "1–2 jours", communes: ["Blida","Boufarik","Bouinan","Ouled Yaich","Beni Mered","Chebli","Mouzaïa","Meftah","Oued El Alleug","Larbaa","Chréa","Soumaa","El Affroun", "Ain Romana", "Ben Khlil", "Beni Tamou", "Bouarfa", "Bougara", "Bouinan", "Chemini", "Djebabra", "El Hamdania", "Guerrouaou", "Hammam Melouane", "Mouzaia", "Oued Djer", "Ouled Selama", "Souhane", "Tamesguida"] },
  "bouira": { fee: 450, delay: "2–3 jours", communes: ["Bouira","Ain Turk","El Asnam","Sour El Ghozlane","Lakhdaria","Bechloul","Haizer","Bir Ghbalou","Taghzout","El Hachimia","Dirah","El Khabouzia","Maamora", "Aghbalou", "Ahl El Ksar", "Ain Bessam", "Ain El Hadjar", "Ait Laaziz", "Aomar", "Bordj Okhriss", "Bouderbala", "Boukram", "Chorfa", "Dechmia", "Djebahia", "El Adjiba", "El Hakimia", "El Ksour", "Guerrouma", "Hadjera Zerga", "Hanif", "Kadiria", "Lakhdaria", "M'Chedellah", "Mezdour", "Oued El Berdi", "Ouled Rached", "Raouraoua", "Ridane", "Saharidj", "Souk El Khemis", "Taguedit", "Z'barbar"] },
  "tamanrasset": { fee: 900, delay: "5–8 jours", communes: ["Tamanrasset","In Guezzam","In Salah","Tin Zaouatine","Abalessa", "Ain Guezzam", "Ain Salah", "Foggaret Ezzoua", "Idles", "Tazrouk"] },
  "tebessa": { fee: 600, delay: "3–5 jours", communes: ["Tebessa","Bir El Ater","Cheria","El Aouinet","El Kouif","Negrine","Bir Mokadem","El Malabiod","Boukhadra","Morsott", "Ain Zerga", "Bedjene", "Bekkaria", "Bir Dheheb", "Boulhaf Dyr", "El Meridj", "El Ogla", "Ferkane", "Guorriguer", "Hammamet", "Maafa", "Mechroha", "Ouenza", "Oum Ali", "Saf Saf El Ouesra", "Stah Guentis", "Telidjen", "Youkous Les"] },
  "tlemcen": { fee: 500, delay: "2–4 jours", communes: ["Tlemcen","Maghnia","Remchi","Hennaya","Sabra","Chetouane","Ghazaouet","Nedroma","Ain Fezza","Ain Tallout","Bensekrane", "Ain Fetah", "Ain Ghoraba", "Ain Kebira", "Ain Nehala", "Ain Tellout", "Ain Youcef", "Amieur", "Azails", "Bab El Assa", "Beni Bahdel", "Beni Boussaid", "Beni Mester", "Beni Ouarsous", "Beni Semiel", "Beni Snous", "Bouhlou", "Chetouane", "Dar Yaghmouracene", "Djebala", "El Aricha", "El Bouihi", "El Gor", "Fellaoucene", "Hammam Boughrara", "Hennaya", "Honaïne", "Marsa Ben M'Hidi", "Msirda", "Nador", "Oued Lakhdar", "Ouled Mimoun", "Ouled Riyah", "Sebbaa Chioukh", "Sebdou", "Sidi Abdelli", "Sidi Djillali", "Sidi Medjahed", "Souani", "Souahlia", "Terni", "Zenet"] },
  "tiaret": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Tiaret", "Sougueur", "Meghila", "Mahdia", "Aïn Bouchekif", "Rahouia", "Medroussa", "Frenda", "Sidi Ali Mellal", "Oued Lilli", "Aïn Deheb", "Aïn Kermes", "Dahmouni", "Djebilet Rosfa", "Faidja", "Guertoufa", "Hamadia", "Ksar Chellala", "Madna", "Mechraa Sfa", "Medrissa", "Mellakou", "Nadorah", "Naima", "Oued Lilli", "Rechaiga", "Sebaine", "Sebt", "Serghine", "Si Abdelghani", "Sidi Abderrahmane", "Sidi Bakhti", "Sidi Hosni", "Takhemaret", "Tidda", "Tousnina", "Zmalet El Emir Abdelkader"]
  },
  "tizi ouzou": {
    fee: 400,
    delay: "2–3 jours",
    communes: ["Tizi Ouzou", "Azazga", "Aït Yahia", "Larbaâ Nath Irathen", "Ouaguenoun", "Draâ El Mizan", "Makouda", "Freha", "Illoula Oumalou", "Iferhounène", "Tigzirt", "Azeffoun", "Abi Youcef", "Aghrib", "Aïn El Hammam", "Aït Aggouacha", "Aït Bouaddou", "Aït Chafâa", "Aït Khelili", "Aït Mahmoud", "Aït Oumalou", "Aït Toudert", "Aït Yahia Moussa", "Akbil", "Akerrou", "Assi Youcef", "Beni Aïssi", "Beni Douala", "Beni Yenni", "Boghni", "Boudjima", "Bounouh", "Bouzeguène", "Draâ Ben Khedda", "Frikat", "Iboudrarene", "Idjeur", "Iflissen", "Mechtras", "Mizrana", "Ouacif", "Ouadhia", "Oued Aïssi", "Sidi Naâmane", "Souk El Thenine", "Tadmaït", "Timizart", "Tirmitine", "Yakouren", "Zekri"]
  },
  "algiers": {
    fee: 300,
    delay: "1–2 jours",
    communes: ["Alger-Centre", "Sidi M'Hamed", "El Madania", "Belouizdad", "Bab El Oued", "Bologhine", "Casbah", "Oued Koriche", "Bir Mourad Raïs", "El Biar", "Bouzareah", "Birkhadem", "El Harrach", "Baraki", "Oued Smar", "Bachdjerrah", "Hussein Dey", "Kouba", "Bourouba", "Dar El Beïda", "Bab Ezzouar", "Ben Aknoun", "Dely Ibrahim", "Hammamet", "Raïs Hamidou", "Djasr Kasentina", "El Mouradia", "Hydra", "Mohammadia", "Bordj El Kiffan", "El Magharia", "Beni Messous", "Les Eucalyptus", "Birtouta", "Tessala El Merdja", "Ouled Chebel", "Sidi Moussa", "Aïn Taya", "Bordj El Bahri", "El Marsa", "H'Raoua", "Rouïba", "Reghaïa", "Aïn Benian", "Staoueli", "Zeralda", "Mahelma", "Rahmania", "Souidania", "Cheraga", "Ouled Fayet", "El Achour", "Draria", "Douera", "Baba Hassen", "Khraicia", "Saoula"]
  },
  "djelfa": {
    fee: 600,
    delay: "3–5 jours",
    communes: ["Djelfa", "Hassi Bahbah", "Aïn Oussera", "Dar Chioukh", "El Idrissia", "Charef", "Messaad", "Zaâfrane", "El Khemis", "Guernini", "Aïn Chouhada", "Aïn El Ibel", "Aïn Fekka", "Aïn Maabed", "Aïn Oussera", "Amourah", "Ben Haroun", "Beni Yagoub", "Birine", "Bouira Lahdab", "Douis", "El Guedid", "Faidh El Botma", "Guettara", "Had Sahary", "Hassi Fedoul", "Hassi Lazreg", "Moudjebara", "Oum Laadham", "Sed Rahal", "Selmana", "Sidi Baïzid", "Sidi Ladjel", "Tadmit", "Zaccar"]
  },
  "jijel": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Jijel", "Taher", "El Aouana", "Texenna", "Chekfa", "Ziama Mansouriah", "El Milia", "Settara", "Aïn El Kebira", "Aïn Errich", "Bordj T'har", "Boudria Ben Yadjis", "Bouraoui Belhadef", "Boussif Ouled Askeur", "Chahna", "Djimla", "El Ancer", "El Kennar Nouchfi", "Emir Abdelkader", "Erraguene", "Ghebala", "Kaous", "Kheïri Oued Adjoul", "Oudjana", "Ouled Rabah", "Ouled Yahia Khadrouche", "Selma Benziada", "Sidi Abdelaziz", "Sidi Marouf", "Sidi Maârouf"]
  },
  "setif": {
    fee: 550,
    delay: "2–4 jours",
    communes: ["Sétif", "El Eulma", "Aïn Arnat", "Beni Ourtilane", "Babor", "Guenzet", "Bougaâ", "Aïn Oulmene", "Guidjel", "Beni Aziz", "Aïn Abessa", "Aïn Azel", "Aïn El Kebira", "Aïn Lahdjar", "Aïn Legraj", "Aïn Roua", "Aïn Sebt", "Amoucha", "Bazer Sakhra", "Beidha Bordj", "Belaa", "Bellaa", "Beni Chebana", "Beni Fouda", "Beni Hocine", "Beni Mouhli", "Bir El Arch", "Bir Haddada", "Bouandas", "Bousselam", "Dehamcha", "Djemila", "Draâ Kebila", "El Ouricia", "Guelal", "Hammam Guergour", "Hammam Souhna", "Maâouia", "Maâkla", "Mechta Ouled Bourenane", "Mezloug", "Ouled Addouane", "Ouled Sabor", "Ouled Si Ahmed", "Ouled Tebben", "Rasfa", "Salah Bey", "Serdj El Ghoul", "Tachouda", "Talaifacene", "Taya", "Tella"]
  },
  "saida": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Saïda", "Moulay Larbi", "Tircine", "Aïn El Hadjar", "Ouled Khaled", "Doui Thabet", "Hounet", "Aïn Sekhouna", "Aïn Soltane", "El Hassasna", "Maâmora", "Ouled Brahim", "Ouled Brahim", "Sidi Ahmed", "Sidi Amar", "Sidi Boubekeur", "Youb"]
  },
  "skikda": {
    fee: 550,
    delay: "2–4 jours",
    communes: ["Skikda", "Collo", "El Hadaik", "El Harrouch", "Azzaba", "Ben Azzouz", "Filfila", "Ramdane Djamel", "Oum Toub", "Aïn Bouziane", "Aïn Charchar", "Aïn Kechra", "Aïn Zouit", "Beni Bechir", "Beni Oulbane", "Beni Zid", "Bin El Ouiden", "Bouchetata", "Cheraia", "Djendel Saadi Mohamed", "Emdjez Edchich", "Es Sebt", "Grarem", "Hamadi Krouma", "Kanoua", "Kerkera", "Oued Zehour", "Ouled Attia", "Ouled Habbaba", "Ouled Hbaba", "Salah Bouchaour", "Sidi Mezghiche", "Tamalous", "Zerdazas", "Zitouna"]
  },
  "sidi bel abbes": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Sidi Bel Abbès", "Sfisef", "Mostefa Ben Brahim", "Aïn El Berd", "Tessala", "Ben Badis", "Telagh", "Merine", "Tenira", "Makedra", "Aïn Adden", "Aïn El Berd", "Aïn Kada", "Aïn Thrid", "Amarnas", "Bedrabine El Mokrani", "Belarbi", "Benachiba Chelia", "Bir El Hammam", "Boudjebaa El Bordj", "Boukhanefis", "Chetouane Belaila", "Dhaya", "El Hacaiba", "Hassi Dahou", "Hassi Zahana", "Lamtar", "M'Cid", "Marhoum", "Merdja Sidi Abed", "Mezaourou", "Moulay Slissen", "Oued Sebaa", "Oued Sefioun", "Oued Taourira", "Ras El Ma", "Redjem Demouche", "Sehala Thaoura", "Sidi Ali Benyoub", "Sidi Ali Boussidi", "Sidi Chaib", "Sidi Dahou Dehiles", "Sidi Hamadouche", "Sidi Khaled", "Sidi Lahcene", "Sidi Yacoub", "Tabia", "Tafissour", "Taoudmout", "Teghalimet", "Telagh", "Tenezara", "Zerouala"]
  },
  "guelma": {
    fee: 550,
    delay: "2–4 jours",
    communes: ["Guelma", "Bouchegouf", "Aïn Larbi", "Nechmaya", "Oued Zenati", "Bouati Mahmoud", "Belkheir", "Aïn Makhlouf", "Hammam Debagh", "Aïn Ben Beida", "Aïn Reggada", "Aïn Sandel", "Bendaoud", "Beni Mezline", "Bordj Sabat", "Dahouara", "Djeballah Khemissi", "El Fedjoudj", "Guelaat Bou Sbaa", "Hammam Maskhoutine", "Hammam N'bails", "Heliopolis", "Houari Boumediene", "Khezaras", "Medjez Amar", "Medjez Sfa", "Nadorah", "Oued Cheham", "Oued Ferragha", "Ras El Agba", "Roknia", "Sellaoua Announa", "Tamlouka"]
  },
  "constantine": {
    fee: 500,
    delay: "2–3 jours",
    communes: ["Constantine", "El Khroub", "Zighout Youcef", "Aïn Smara", "Didouche Mourad", "Ibn Ziad", "Hamma Bouziane", "Aïn Abid", "Ben Badis", "El Haria", "El Koura", "Ibn Ziad", "Messaoud Boudjeriou", "Ouled Rahmoune"]
  },
  "mostaganem": {
    fee: 450,
    delay: "2–3 jours",
    communes: ["Mostaganem", "Aïn Tedles", "Bouguirat", "Hassi Mameche", "Mesra", "Sirat", "Achaacha", "Sidi Ali", "Fornaka", "Kheïr Eddine", "Aïn Boudinar", "Aïn Nouissy", "Benabdelmalek Ramdane", "Bir El Djir", "Bouguirat", "Dar Yaghmoracene", "Fornaka", "Hadjadj", "Hassi Maameche", "Khadra", "Mansourah", "Mazagran", "Nekmaria", "Oued El Kheïr", "Ouled Boughalem", "Ouled Maallah", "Safsaf", "Sayada", "Sidi Bellater", "Sidi Lakhdar", "Souaflia", "Sour", "Stidia", "Tazgait", "Touahria"]
  },
  "msila": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["M'sila", "Ouled Derradj", "Sidi Aïssa", "Aïn El Hadjel", "Bou Saâda", "Ben Srour", "Maadid", "Hammam Dhalaâ", "Magra", "Aïn El Melh", "Aïn Fares", "Aïn Khadra", "Belaïba", "Beni Ilmane", "Benzouh", "Berhoum", "Bir Foda", "Bouti Sayah", "Chellal", "Dehahna", "Djebel Messaad", "El Hamel", "El Houamed", "Khettouti Sed El Jouli", "Khoubana", "M'Tarfa", "Menaa", "Mohamed Boudiaf", "Ouanougha", "Ouled Addi Guebala", "Ouled Atia", "Ouled Madhi", "Ouled Mansour", "Ouled Sidi Brahim", "Oultem", "Sidi Ameur", "Sidi Hadjeres", "Slim", "Souamaa", "Tamsa", "Tarmount", "Zarzour"]
  },
  "mascara": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Mascara", "Sig", "Ghriss", "Bouhanifia", "Oued Taria", "Froha", "Tizi", "El Bordj", "Zahana", "Aïn Fekan", "Aïn Ferah", "Aïn Fras", "Aïn Fekan", "Alaimia", "Aouf", "Benian", "Bou Henni", "Chorfa", "El Gaada", "El Ghomri", "El Gueitena", "El Keurt", "Ferraguig", "Gharrous", "Guerdjoum", "Hacine", "Khalouia", "Makhda", "Maoussa", "Moha Ou Ali", "Nesmoth", "Oggaz", "Oued El Abtal", "Ras El Ain Amirouche", "Sedjerara", "Sehailia", "Sidi Abdeldjebar", "Sidi Abdelmoumene", "Sidi Boussaid", "Sidi Kada", "Tighennif", "Zahana", "Zelamta"]
  },
 "ouargla": {
    fee: 700,
    delay: "4–6 jours",
    communes: ["Ouargla", "Hassi Messaoud", "Rouissat", "N'Goussa", "Sidi Khouiled", "Aïn Beida", "Touggourt", "El Hadjira", "Benaceur", "Blidet Amor", "El Alia", "El Borma", "El Haoud", "Hassi Ben Abdellah", "M'Naguer", "Nezla", "Sidi Slimane", "Taïbet"]
  },
  "oran": {
    fee: 400,
    delay: "2–3 jours",
    communes: ["Oran", "Es Senia", "Arzew", "Gdyel", "Bir El Djir", "Hassi Bounif", "Mers El Kebir", "Aïn El Turk", "Bethioua", "Sidi Chami", "Aïn Biya", "Ben Freha", "Boufatis", "Bousfer", "El Ançor", "El Braya", "El Kerma", "Hassi Ben Okba", "Hassi Bounif", "Hassi Mefsoukh", "Misserghin", "Oued Tlelat", "Sidi Benyebka", "Tafraoui"]
  },
  "el bayadh": {
    fee: 750,
    delay: "4–6 jours",
    communes: ["El Bayadh", "Bougtob", "Rogassa", "Brezina", "Labiodh Sidi Cheikh", "Chellala", "Arbaouat", "Ghassoul", "Boussemghoun", "Boualem", "Cheheima", "El Abiodh Sidi Cheikh", "El Bnoud", "El Kheither", "Kef El Ahmar", "Krakda", "Rogassa", "Sidi Ameur", "Sidi Slimane", "Sidi Tiffour", "Stitten", "Tousmouline"]
  },
  "bordj bou arreridj": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Bordj Bou Arreridj", "Rabta", "Zemmoura", "El Hamadia", "El Achir", "Hasnaoua", "Aïn Taghrout", "Djaafra", "Mansoura", "Medjana", "Aïn Tesra", "Belimour", "Ben Daoud", "Bir Kasdali", "Bordj Ghedir", "Bordj Zemmoura", "Colla", "Djerrah", "El Euch", "El M'hir", "Ghilassa", "Haraza", "Ksour", "M'Cif", "Ouled Brahem", "Ouled Dahmane", "Ouled Sidi Brahim", "Ras El Oued", "Sidi Embarek", "Taglait", "Tassameurt", "Tefreg", "Teniet En Nasr", "Tixter"]
  },
  "boumerdes": {
    fee: 350,
    delay: "1–2 jours",
    communes: ["Boumerdès", "Dellys", "Thenia", "Boudouaou", "Khemis El Khechna", "Naciria", "Si Mustapha", "Bordj Menaiel", "Ouled Moussa", "Tidjelabine", "Afir", "Ammal", "Baghlia", "Ben Choud", "Beni Amrane", "Boudouaou El Bahri", "Bouzegza Keddara", "Chabet El Ameur", "Corso", "Djinet", "Isser", "Khemis El Khechna", "Larbatache", "Leghata", "Ouled Aissa", "Ouled Hedadj", "Ouled Haddadj", "Taourga", "Timezrit", "Zemmouri"]
  },
  "el tarf": {
    fee: 600,
    delay: "3–5 jours",
    communes: ["El Tarf", "Bouhadjar", "Ben M'Hidi", "Bouteldja", "Souarekh", "El Kala", "Berrihane", "Raml Souk", "Zitouna", "Aïn El Assel", "Aïn Kerma", "Asfour", "Ben Mehdi", "Bougous", "Chebaita Mokhtar", "Chihani", "Echatt", "Zerizer", "Zitouna"]
  },
  "tindouf": {
    fee: 1000,
    delay: "6–9 jours",
    communes: ["Tindouf", "Oum El Assel"]
  },
  "tissemsilt": {
    fee: 500,
    delay: "3–5 jours",
    communes: ["Tissemsilt", "Bordj Bounaama", "Lardjem", "Beni Chaib", "Theniet El Had", "Khémisti", "Melaab", "Bordj Emir Abdelkader", "Sidi Boutouchent", "Ammari", "Beni Lahcene", "Bordj El Emir Abdelkader", "Boucaid", "Khemisti", "Larbaa", "Layoune", "Maacem", "Sidi Abed", "Sidi Slimane", "Tamellahet", "Youssoufia"]
  },
  "el oued": {
    fee: 700,
    delay: "4–6 jours",
    communes: ["El Oued", "Djamaa", "Bayoudh", "Mih Ouensa", "Robbah", "Reguiba", "Kouinine", "Guemar", "Taghzout", "Beni Guecha", "Douar El Ma", "El Ogla", "Hassani Abdelkrim", "Magrane", "Mih Ouansa", "Nakhla", "Oued El Alenda", "Oum Touyour", "Sidi Amrane", "Sidi Khellil", "Still", "Taleb Larbi", "Trifaoui"]
  },
  "khenchela": {
    fee: 600,
    delay: "3–5 jours",
    communes: ["Khenchela", "Chelia", "Chechar", "El Hamma", "Baghai", "Bouhmama", "Aïn Touila", "Kais", "Tamza", "Bab El Assa", "Bouaichoune", "Djellal", "El Mahmal", "Ensigha", "Ferkane", "Khirane", "M'Sara", "M'toussa", "Ouled Rechache", "Remila", "Taouzianat", "Yabous"]
  },
  "souk ahras": {
    fee: 600,
    delay: "3–5 jours",
    communes: ["Souk Ahras", "Taoura", "Bir Bouhouche", "Heddada", "Mechroha", "Sedrata", "Oum El Adhaim", "Ouled Driss", "Ouillen", "Zaarouria", "Khedara", "Aïn Zana", "Drea", "Hanencha", "Khemissa", "Merahna", "Oued Keberit", "Ouled Moumen", "Ragouba", "Safel El Ouiden", "Sidi Fredj", "Terraguelt", "Tiffech", "Zouabi"]
  },
  "tipaza": {
    fee: 350,
    delay: "1–2 jours",
    communes: ["Tipaza", "Merad", "Koléa", "Bou Ismail", "Cherchell", "Hadjout", "Sidi Amar", "Fouka", "Aïn Tagourait", "Menaceur", "Ahmar El Aïn", "Aïn Defla", "Aïn Taggourait", "Attatba", "Bou Haroun", "Bourkika", "Chaiba", "Damous", "Douaouda", "Gouraya", "Hadjeret Ennous", "Khemisti", "Larhat", "Messelmoun", "Nador", "Sidi Ghiles", "Sidi Rached", "Sidi Semiane"]
  },
  "mila": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Mila", "Tikrirt", "Sidi Merouane", "Chelghoum Laïd", "Ferdjioua", "Tassadane Haddada", "Rouached", "Grah Bou Noura", "Hamala", "Aïn Beida Harriche", "Aïn Mellouk", "Amira Arras", "Benyahia Abderrahmane", "Bouhatem", "Chigara", "Derradji Bousselah", "El Ayadi Barbes", "El Mechira", "Oued Athmania", "Oued Endja", "Oued Seguen", "Ouled Khalouf", "Sidi Khelifa", "Tadjenanet", "Tassadane Haddada", "Teleghma", "Terrai Bainen", "Terrai Bainen", "Tiberguent", "Yahia Beni Guecha", "Zeghaia"]
  },
 "ain defla": {
    fee: 400,
    delay: "2–3 jours",
    communes: ["Aïn Defla", "El Abadia", "Miliana", "Boumedfaa", "El Amra", "Djelida", "Tacheta Zougagha", "Rouina", "Khemis Miliana", "Bordj Emir Khaled", "Aïn Benian", "Aïn Bouyahia", "Aïn Lechiekh", "Aïn Soltane", "Aïn Torki", "Bathia", "Belaas", "Ben Allal", "Birbouche", "Bordj Emir Khaled", "Boumedfaa", "Djemaa Ouled Cheikh", "El Attaf", "El Hassania", "El Maine", "Hammam Righa", "Hoceinia", "Mekhatria", "Oued Chorfa", "Oued Djemaa", "Rouina", "Sidi Lakhdar", "Tarik Ibn Ziad", "Tiberkanine", "Zeddine"]
  },
  "naama": {
    fee: 750,
    delay: "4–6 jours",
    communes: ["Naâma", "Mécheria", "Sfissifa", "Aïn Sefra", "Kasdir", "Tiout", "El Biodh", "Assela", "Aïn Ben Khelil", "Djeniane Bourzeg", "Mekmen Ben Amar", "Moghrar", "Ouargla", "Sidi Boumediene", "Tiout"]
  },
  "ain temouchent": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Aïn Témouchent", "Sidi Safi", "El Amria", "Hammam Bouhadjar", "Oulhaca El Gheraba", "El Malah", "Aghlal", "Chaabat El Ham", "Aïn El Arbaa", "Aïn Kihal", "Aïn Tolba", "Beni Saf", "Bouzedjar", "Chentouf", "El Emir Abdelkader", "Hassasna", "Hassi El Ghella", "Oued Berkeche", "Oued Sebbah", "Ouled Boudjemaa", "Ouled Kihal", "Sidi Ben Adda", "Sidi Ouriache", "Tamzoura", "Terga"]
  },
  "ghardaia": {
    fee: 700,
    delay: "4–6 jours",
    communes: ["Ghardaïa", "El Atteuf", "Metlili", "Berriane", "El Guerrara", "Zelfana", "Dhayet Bendhahoua", "Bounoura", "Dhayet Bendhahoua", "El Meniaa", "Sebseb"]
  },
  "relizane": {
    fee: 500,
    delay: "2–4 jours",
    communes: ["Relizane", "Oued Rhiou", "Mansourah", "Yellel", "Mazouna", "Ammi Moussa", "El H'Madna", "Ouled Sidi Mihoub", "Mediouna", "Sidi Saâda", "Aïn Rahma", "Aïn Tarek", "Bendaoud", "Beni Dergoun", "Beni Zentis", "Dar Ben Abdellah", "Djidioua", "El Guettar", "El Hamri", "El Matmar", "El Ouldja", "Had Echkalla", "Hamri", "Kalaa", "Lahlef", "Mendes", "Merine", "Merrahi", "Oued Essalem", "Ouled Aiche", "Ouled Sidi Lazreg", "Ramka", "Sidi Khettab", "Sidi Lazreg", "Sidi M'Hamed Ben Ali", "Sidi M'Hamed Benaouda", "Souk El Had", "Zemmora"]
  },
"el mghair": {
    fee: 700,
    delay: "4–6 jours",
    communes: ["El M'Ghair", "Djamaa", "Oum Touyour", "Sidi Amrane", "Still", "Taleb Larbi", "Trifaoui"]
  },
  "el menia": {
    fee: 750,
    delay: "4–6 jours",
    communes: ["El Menia", "Hassi Messaoud", "Hassi Gara", "El Borma", "El Haoud", "Hassi Ben Abdellah"]
  },
  "ouled djellal": {
    fee: 650,
    delay: "4–6 jours",
    communes: ["Ouled Djellal", "Sidi Khaled", "Doucen", "Besbes", "Chaiba", "Ras El Miad", "Sidi Okba"]
  },
  "beni abbes": {
    fee: 800,
    delay: "5–7 jours",
    communes: ["Beni Abbes", "Tamtert", "El Ouata", "Ouled Khoudir", "Igli", "Kerzaz", "Taghit"]
  },
  "timimoun": {
    fee: 800,
    delay: "5–7 jours",
    communes: ["Timimoun", "Tinerkouk", "Ouled Said", "Aougrout", "Charouine", "Deldoul", "Metarfa", "Ouled Aissa"]
  },
  "touggourt": {
    fee: 700,
    delay: "4–6 jours",
    communes: ["Touggourt", "Megarine", "Nezla", "Sidi Slimane", "Blidet Amor", "Benaceur", "Taïbet"]
  },
  "djanet": {
    fee: 950,
    delay: "6–9 jours",
    communes: ["Djanet", "Bordj El Haouass", "Illizi", "Debdeb", "In Amenas"]
  },
  "in salah": {
    fee: 850,
    delay: "6–9 jours",
    communes: ["In Salah", "Foggaret Ezzoua", "Ain Salah Sud", "Foggaret Ezzaouia", "In Salah Nord"]
  },
  "in guezzam": {fee: 1000,delay: "7–10 jours",communes: ["In Guezzam", "Tin Zouatine", "Taessa", "Ain Guezzam"]
  },
"annaba": { fee: 500, delay: "2–3 jours", communes: [
    "Annaba", "El Bouni", "El Hadjar", "Sidi Amar", "Treat", "Aïn Berda", "Berrahal", 
    "Cheurfa", "Chetaïbi", "Echatt", "El Eulma", "Oued El Aneb", "Serraïdi", 
    "Sidi Salem", "Oued Kouba", "Bouchegouf", "Aïn Charchar", "Zighoud Youcef"
  ]
},
"illizi": {  fee: 950, delay: "6–9 jours", communes: [
    "Illizi", "Djanet", "In Amenas", "Bordj El Haouass", "Debdeb", "Tin Alkoum"
  ]
},
"medea": { fee: 450, delay: "2–3 jours", communes: [
    "Médéa", "Berrouaghia", "Ksar El Boukhari", "Aïn Boucif", "Aziz", "Beni Slimane", 
    "Bouaichoune", "Boumedfaa", "Chabounia", "Chelalet El Adhaoura", "Derrag", 
    "Draa Essamar", "El Azizia", "El Omaria", "Guelb El Kébir", "Kef Lakhdar", 
    "Mezerana", "Ouamri", "Ouled Antar", "Ouled Bouachra", "Ouled Deide", 
    "Ouled Hellal", "Ouled Maaref", "Rebaia", "Saneg", "Sedraia", "Seghouane", 
    "Si Mahdjoub", "Sidi Demed", "Sidi Naamane", "Souagui", "Tablat", "Tafraout", 
    "Tamesguida", "Tizi Mahdi", "Tlatet Eddouair", "Zoubiria"
  ]
},
"bordj badji mokhtar": { fee: 900, delay: "5–8 jours", communes: ["Bordj Badji Mokhtar", "Timiaouine", "Zaouiet Kounta"]}
};
      

// ===== POST /checkout - FIXED WITH WHATSAPP + TELEGRAM =====
// POST /checkout
router.post("/checkout", async (req, res) => {
  if (!req.session.cart) return res.redirect("/shop");
  const cart = new Cart(req.session.cart);
  const freeShippingThreshold = 5000;
  const { firstName, lastName, address, city, commune, numero: rawNumero, paymentMethod } = req.body;

  if (!firstName?.trim() || !lastName?.trim() || !address?.trim() || !city?.trim() || !commune?.trim()) {
    req.flash("error", "Merci de remplir tous les champs obligatoires.");
    return res.redirect("/checkout");
  }
  if (!isValidAlgerianNumero(rawNumero)) {
    req.flash("error", "Numéro de téléphone invalide.");
    return res.redirect("/checkout");
  }

  const cityNormalised = (city || "").toLowerCase().trim();
  const shippingInfo = wilayaShippingInfo[cityNormalised] || { fee: 1000, delay: "3-5 jours" };
  let shippingFee = cart.totalPrice >= freeShippingThreshold ? 0 : shippingInfo.fee;

  // Process Coupon Code Discount if provided
  const { couponCode } = req.body;
  let couponDiscount = 0;
  if (couponCode && couponCode.trim()) {
    try {
      const coupon = await Coupon.findOne({ code: couponCode.trim().toUpperCase(), active: true });
      if (coupon && coupon.isValid(cart.totalPrice)) {
        if (coupon.discountType === 'percent') {
          couponDiscount = (cart.totalPrice * coupon.discountValue) / 100;
        } else {
          couponDiscount = Math.min(cart.totalPrice, coupon.discountValue);
        }
        coupon.usageCount = (coupon.usageCount || 0) + 1;
        await coupon.save();
      }
    } catch(e) {
      console.warn("Coupon process warning:", e.message);
    }
  }

  const finalTotalPrice = Math.max(0, cart.totalPrice - couponDiscount + shippingFee);

  // 1. COD
  if (paymentMethod === "cod") {
    try {
      const cleanNumero = "213" + rawNumero.replace(/^0+/, "").replace(/\D/g, "");
      const userData = getCleanUserData(req);
      const order = new Order({
        user: req.user || null,
        cart: cart,
        address, firstName, lastName, commune,
        country: "Algeria",
        city: cityNormalised,
        numero: cleanNumero,
        shippingFee,
        deliveryDelay: shippingInfo.delay,
        orderType: req.user ? "user" : "guest",
        totalWithShipping: finalTotalPrice,
        paymentMethod: "cod",
        metaUserData: userData || {},
      });
      await order.save();

      // Decrement product stock
      if (cart.items) {
        for (const key in cart.items) {
          const itemObj = cart.items[key];
          const qty = itemObj.qty || 1;
          const item = itemObj.item || {};
          const productId = (item._id || key).toString();

          if (mongoose.isValidObjectId(productId)) {
            const ph = await Producthome.findById(productId);
            if (ph) {
              const currentStock = typeof ph.stock === 'number' ? ph.stock : 10;
              const newStock = Math.max(0, currentStock - qty);
              ph.stock = newStock;
              if (newStock <= 0) ph.disponible = false;
              await ph.save().catch(() => {});

              if (newStock <= 3) {
                sendTelegramMessage(`⚠️ <b>ALERTE STOCK FAIBLE</b>\n📦 Produit: ${ph.title}\n📉 Stock restant: <b>${newStock}</b> unités !`).catch(()=>{});
              }
            }
            const pt = await Paintello.findById(productId);
            if (pt) {
              const currentStock = typeof pt.stock === 'number' ? pt.stock : 10;
              const newStock = Math.max(0, currentStock - qty);
              pt.stock = newStock;
              if (newStock <= 0) pt.disponible = false;
              await pt.save().catch(() => {});

              if (newStock <= 3) {
                sendTelegramMessage(`⚠️ <b>ALERTE STOCK FAIBLE</b>\n📦 Produit: ${pt.title}\n📉 Stock restant: <b>${newStock}</b> unités !`).catch(()=>{});
              }
            }
          }
        }
      }

      const eventIds = req.session.preGeneratedEventIds || {};
      const eventIdInitiateCheckout = eventIds.initiateCheckout || generateEventId();
      const testCode = eventIds.testCode || getTestCode(req);

      if (userData) {
        sendFacebookCAPIEvent({
          eventName: "InitiateCheckout",
          eventId: eventIdInitiateCheckout,
          userData,
          customData: {
            content_ids: cart.generateArray().map(p => p.item._id.toString()),
            contents: cart.generateArray().map(p => ({ id: p.item._id.toString(), quantity: p.qty, item_price: p.item.price })),
            content_type: "product",
            value: finalTotalPrice,
            currency: "DZD",
            num_items: cart.totalQty || 0,
          },
          eventSourceUrl: getEventSourceUrl(req),
          testEventCode: testCode,
        }).catch(()=>{});
        console.log("✅ CAPI InitiateCheckout sent for COD", eventIdInitiateCheckout);
      }

      // WHATSAPP COD
      const waPayloadCOD = {
        messaging_product: "whatsapp",
        to: cleanNumero,
        type: "template",
        template: {
          name: "commande_confirmee",
          language: { code: "fr" },
          components: [
            { type: "header", parameters: [{ type: "image", image: { link: "https://www.paintello.uk/img/logo.png" } }] },
            {
              type: "body",
              parameters: [
                { type: "text", text: firstName || "Client" },
                { type: "text", text: cart.totalPrice.toString() + " DZD" },
                { type: "text", text: shippingFee === 0 ? "GRATUIT" : shippingFee.toString() + " DZD" },
                { type: "text", text: finalTotalPrice.toString() + " DZD" },
                { type: "text", text: shippingInfo.delay },
                { type: "text", text: `${address}, ${cityNormalised}` }
              ]
            }
          ]
        }
      };
      try {
        const waRes = await axios.post(`https://graph.facebook.com/v19.0/${process.env.META_PHONE_ID}/messages`, waPayloadCOD, {
          headers: { Authorization: `Bearer ${process.env.META_WA_TOKEN}`, 'Content-Type': 'application/json' }
        });
        console.log("✅ WhatsApp COD sent:", waRes.data.messages?.[0]?.id);
      } catch (err) {
        console.error("❌ WhatsApp COD error:", err.response?.data || err.message);
      }

      // TELEGRAM COD - with deliver link
      try {
        await sendTelegramMessage(
          `🛒 <b>Nouvelle commande COD</b> — ${order.firstName} ${order.lastName}\n` +
          `📱 Tél: ${order.numero}\n` +
          `📍 Adresse: ${order.address}, ${order.commune}, ${order.city}\n` +
          `💰 Total: ${order.totalWithShipping} DZD\n` +
          `🚚 Livraison: ${order.deliveryDelay}\n` +
          `📦 Statut: ${order.status}\n` +
          `💳 Paiement: Paiement à la livraison\n` +
          `🔗 Marquer livrée: https://www.paintello.uk/order/deliver/${order._id}?secret=${encodeURIComponent(process.env.DELIVERY_SECRET)}`
        );
        console.log("✅ Telegram COD sent");
      } catch (e) {
        console.error("❌ Telegram COD failed:", e.response?.data || e.message);
      }

      req.session.cart = null;
      if (req.session.preGeneratedEventIds) delete req.session.preGeneratedEventIds.initiateCheckout;

      req.session.confirmationData = {
        orderId: order._id.toString(),
        paymentMethod: "cod",
        eventId: eventIdInitiateCheckout,
        eventName: "InitiateCheckout",
        testEventCode: testCode,
        firstName, lastName, numero: cleanNumero, address,
        city: cityNormalised, commune,
        cartTotal: cart.totalPrice,
        shippingFee,
        deliveryDelay: shippingInfo.delay,
        totalPrice: finalTotalPrice,
        cartItems: cart.generateArray(),
        isFreeShipping: cart.totalPrice >= freeShippingThreshold,
      };
      return res.redirect("/confirmation");
    } catch (err) {
      console.error("COD error:", err);
      req.flash("error", "Erreur lors de la commande.");
      return res.redirect("/checkout");
    }
  }

  // 2. CHARGILY
  const userDataForLater = getCleanUserData(req);
  const testCode = getTestCode(req);
  req.session.pendingOrder = {
    cart: req.session.cart,
    firstName, lastName, address,
    city: cityNormalised, commune,
    shippingFee,
    shippingDelay: shippingInfo.delay,
    finalTotalPrice,
    rawNumero,
    processed: false,
    user: req.user || null,
    savedUserData: userDataForLater,
    testCode: testCode
  };

  const baseUrl = `${req.protocol}://${req.get("host")}`;
  try {
    const payment = await createPayment({
      amount: Math.round(finalTotalPrice),
      currency: "dzd",
      success_url: `${baseUrl}/payment/success`,
      failure_url: `${baseUrl}/checkout?payment=failed`,
      metadata: { session_id: req.sessionID },
    });
    return res.redirect(payment.checkout_url);
  } catch (error) {
    console.error("❌ Chargily error:", error);
    req.flash("error", "Erreur création paiement.");
    return res.redirect("/checkout");
  }
});

// GET /payment/success - CHARGILY - Purchase + WhatsApp + Telegram
router.get("/payment/success", async (req, res) => {
  const checkoutId = req.query.checkout_id;
  if (!checkoutId || !req.session.pendingOrder) return res.redirect("/checkout");
  if (req.session.pendingOrder.processed) {
    if (req.session.lastOrderId) return res.redirect(`/confirmation?order_id=${req.session.lastOrderId}`);
    req.flash("success", "Votre commande a déjà été confirmée.");
    return res.redirect("/");
  }

  req.session.pendingOrder.processed = true;
  await new Promise((resolve, reject) => { req.session.save((err) => (err ? reject(err) : resolve())); });

  try {
    const checkout = await verifyPayment(checkoutId);
    if (checkout.status !== "paid") {
      req.flash("error", "Le paiement n'a pas abouti.");
      return res.redirect("/checkout");
    }

    const pending = req.session.pendingOrder;
    const cart = new Cart(pending.cart);
    const cleanNumero = "213" + pending.rawNumero.replace(/^0+/, "").replace(/\D/g, "");
    const order = new Order({
      user: pending.user,
      cart: cart,
      address: pending.address,
      firstName: pending.firstName,
      lastName: pending.lastName,
      commune: pending.commune,
      country: "Algeria",
      city: pending.city,
      numero: cleanNumero,
      shippingFee: pending.shippingFee,
      deliveryDelay: pending.shippingDelay,
      orderType: pending.user ? "user" : "guest",
      totalWithShipping: pending.finalTotalPrice,
      paymentMethod: "chargily"
    });
    await order.save();

    // Decrement product stock for Chargily orders
    if (cart.items) {
      for (const key in cart.items) {
        const itemObj = cart.items[key];
        const qty = itemObj.qty || 1;
        const item = itemObj.item || {};
        const productId = (item._id || key).toString();

        if (mongoose.isValidObjectId(productId)) {
          const ph = await Producthome.findById(productId);
          if (ph) {
            const currentStock = typeof ph.stock === 'number' ? ph.stock : 10;
            const newStock = Math.max(0, currentStock - qty);
            ph.stock = newStock;
            if (newStock <= 0) ph.disponible = false;
            await ph.save().catch(() => {});
          }
          const pt = await Paintello.findById(productId);
          if (pt) {
            const currentStock = typeof pt.stock === 'number' ? pt.stock : 10;
            const newStock = Math.max(0, currentStock - qty);
            pt.stock = newStock;
            if (newStock <= 0) pt.disponible = false;
            await pt.save().catch(() => {});
          }
        }
      }
    }
    req.session.lastOrderId = order._id;
    await new Promise((resolve, reject) => { req.session.save((err) => (err ? reject(err) : resolve())); });

    const eventIdPurchase = generateEventId();
    const userData = pending.savedUserData || getCleanUserData(req);
    const testCode = pending.testCode || getTestCode(req);
    if (userData && Object.keys(userData).length > 0) {
      sendFacebookCAPIEvent({
        eventName: "Purchase",
        eventId: eventIdPurchase,
        userData,
        customData: {
          value: pending.finalTotalPrice,
          currency: "DZD",
          content_type: "product",
          content_ids: cart.generateArray().map(p => p.item._id.toString()),
          contents: cart.generateArray().map(p => ({ id: p.item._id.toString(), quantity: p.qty, item_price: p.item.price })),
        },
        eventSourceUrl: getEventSourceUrl(req),
        testEventCode: testCode,
      }).catch(()=>{});
      console.log("✅ CAPI Purchase sent for Chargily", eventIdPurchase);
    }

    // TELEGRAM CHARGILY
    try {
      await sendTelegramMessage(
        `🛒 <b>Nouvelle commande CIB/Edahabia PAYÉE</b> — ${pending.firstName} ${pending.lastName}\n` +
        `📱 Tél: ${cleanNumero}\n` +
        `📍 Adresse: ${pending.address}, ${pending.commune}, ${pending.city}\n` +
        `💰 Total: ${pending.finalTotalPrice} DZD\n` +
        `🚚 Livraison: ${pending.shippingDelay}\n` +
        `📦 Statut: Payé\n` +
        `💳 Paiement: CIB/Edahabia\n` +
        `🔗 Voir: https://www.paintello.uk/order/deliver/${order._id}?secret=${encodeURIComponent(process.env.DELIVERY_SECRET)}`
      );
      console.log("✅ Telegram Chargily sent");
    } catch (err) { console.error('❌ Telegram Chargily error:', err.message); }

    // WHATSAPP CHARGILY
    const waPayloadChargily = {
      messaging_product: "whatsapp",
      to: cleanNumero,
      type: "template",
      template: {
        name: "commande_confirmee",
        language: { code: "fr" },
        components: [
          { type: "header", parameters: [{ type: "image", image: { link: "https://www.paintello.uk/img/logo.png" } }] },
          {
            type: "body",
            parameters: [
              { type: "text", text: pending.firstName || "Client" },
              { type: "text", text: cart.totalPrice.toString() + " DZD" },
              { type: "text", text: pending.shippingFee === 0 ? "GRATUIT" : pending.shippingFee.toString() + " DZD" },
              { type: "text", text: pending.finalTotalPrice.toString() + " DZD" },
              { type: "text", text: pending.shippingDelay },
              { type: "text", text: `${pending.address}, ${pending.city}` },
            ],
          },
        ],
      },
    };
    try {
      await axios.post(`https://graph.facebook.com/v19.0/${process.env.META_PHONE_ID}/messages`, waPayloadChargily, {
        headers: { Authorization: `Bearer ${process.env.META_WA_TOKEN}`, 'Content-Type': 'application/json' }
      });
      console.log("✅ WhatsApp Chargily sent");
    } catch (err) {
      console.error("❌ WhatsApp Chargily error:", err.response?.data || err.message);
    }

    req.session.cart = null;
    req.session.pendingOrder = null;
    req.session.confirmationData = {
      orderId: order._id.toString(),
      paymentMethod: "chargily",
      eventId: eventIdPurchase,
      eventName: "Purchase",
      testEventCode: testCode,
      value: pending.finalTotalPrice,
      currency: "DZD",
      content_ids: cart.generateArray().map(p => p.item._id.toString()),
      contents: cart.generateArray().map(p => ({ id: p.item._id.toString(), quantity: p.qty, item_price: p.item.price, item_name: p.item.title })),
      firstName: pending.firstName,
      lastName: pending.lastName,
      numero: cleanNumero,
      address: pending.address,
      city: pending.city,
      commune: pending.commune,
      cartTotal: cart.totalPrice,
      shippingFee: pending.shippingFee,
      deliveryDelay: pending.shippingDelay,
      totalPrice: pending.finalTotalPrice,
      cartItems: cart.generateArray(),
      isFreeShipping: cart.totalPrice >= 5000,
    };
    return res.redirect(`/confirmation?order_id=${order._id}`);
  } catch (error) {
    req.session.pendingOrder.processed = false;
    console.error("❌ Payment verification error:", error);
    req.flash("error", "Erreur vérification paiement.");
    return res.redirect("/checkout");
  }
});

// GET /confirmation
router.get("/confirmation", async (req, res) => {
  let data = req.session.confirmationData;
  const orderId = req.query.order_id;
  if (!data && orderId) {
    try {
      if (!isValidObjectId(orderId)) return res.redirect("/");
      const order = await Order.findById(orderId);
      if (order) {
        data = {
          orderId: order._id.toString(),
          paymentMethod: order.paymentMethod || "cod",
          eventId: null,
          eventName: null,
          testEventCode: getTestCode(req),
          firstName: order.firstName,
          lastName: order.lastName,
          numero: order.numero,
          address: order.address,
          city: order.city,
          commune: order.commune,
          cartTotal: order.cart.totalPrice,
          shippingFee: order.shippingFee,
          deliveryDelay: order.deliveryDelay,
          totalPrice: order.totalWithShipping,
          cartItems: order.cart.generateArray ? order.cart.generateArray() : [],
          isFreeShipping: order.cart.totalPrice >= 5000,
        };
      }
    } catch (err) { console.error(err); }
  }
  if (!data) return res.redirect("/");
  const eventIdPageView = generateEventId();
  const userData = getCleanUserData(req);
  const testCode = data.testEventCode || getTestCode(req);
  if (userData) {
    setFbcCookieIfNeeded(req, res, userData);
    sendFacebookCAPIEvent({
      eventName: "PageView",
      eventId: eventIdPageView,
      userData,
      eventSourceUrl: getEventSourceUrl(req),
      customData: {},
      testEventCode: testCode,
    }).catch(()=>{});
  }
  const renderData = { ...data, metaEventIdPageView: eventIdPageView, user: req.user, req };
  res.render("event/confirmation", renderData, (err, html) => {
    req.session.confirmationData = null;
    if (err) { console.error(err); return res.status(500).send("Erreur"); }
    res.send(html);
  });
});

// GET /order/deliver/:orderId - Mark delivered + Send Purchase for COD
// GET /order/invoice/:orderId - Printable Invoice HTML
router.get("/order/invoice/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;
    if (!isValidObjectId(orderId)) return res.status(404).send("Commande introuvable");

    const order = await Order.findById(orderId).lean();
    if (!order) return res.status(404).send("Commande introuvable");

    const cart = new Cart(order.cart || {});
    const items = cart.generateArray();
    const formattedDate = new Date(order.createdAt).toLocaleDateString('fr-FR', {
      year: 'numeric', month: 'long', day: 'numeric'
    });

    res.send(`
      <!DOCTYPE html>
      <html lang="fr">
      <head>
        <meta charset="utf-8">
        <title>Facture #${order._id} — Paintello Home</title>
        <style>
          body { font-family: 'Helvetica Neue', Arial, sans-serif; padding: 40px; color: #111; max-width: 800px; margin: 0 auto; background: #fff; }
          .header { display: flex; justify-content: space-between; align-items: center; border-b: 2px solid #111; padding-bottom: 20px; margin-bottom: 30px; }
          .logo { font-size: 24px; font-weight: bold; letter-spacing: 2px; text-transform: uppercase; }
          .invoice-title { font-size: 18px; text-transform: uppercase; color: #555; }
          .grid { display: flex; justify-content: space-between; margin-bottom: 30px; font-size: 13px; line-height: 1.6; }
          table { w-full; width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 13px; }
          th { text-align: left; padding: 10px; border-bottom: 2px solid #ddd; text-transform: uppercase; font-size: 11px; }
          td { padding: 12px 10px; border-bottom: 1px solid #eee; }
          .totals { text-align: right; font-size: 14px; line-height: 1.8; }
          .grand-total { font-size: 18px; font-weight: bold; color: #000; border-top: 2px solid #111; padding-top: 10px; margin-top: 10px; }
          .no-print { margin-top: 40px; text-align: center; }
          .btn-print { padding: 12px 25px; background: #111; color: #fff; border: none; font-size: 12px; text-transform: uppercase; font-weight: bold; cursor: pointer; border-radius: 4px; }
          @media print { .no-print { display: none; } }
        </style>
      </head>
      <body>
        <div class="header">
          <div class="logo">PAINTELLO HOME</div>
          <div class="invoice-title">Facture N° #${order._id.toString().substring(0, 8)}</div>
        </div>

        <div class="grid">
          <div>
            <strong>Facturé à:</strong><br>
            ${order.firstName} ${order.lastName}<br>
            Tél: ${order.formattedPhone || order.numero}<br>
            ${order.address}<br>
            ${order.commune}, ${order.city} (Algérie)
          </div>
          <div style="text-align: right;">
            <strong>Date de commande:</strong> ${formattedDate}<br>
            <strong>Mode de paiement:</strong> ${order.paymentMethod === 'chargily' ? 'Carte CIB/Edahabia' : 'Paiement à la livraison'}<br>
            <strong>Statut:</strong> ${order.status.toUpperCase()}
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Description</th>
              <th style="text-align: center;">Quantité</th>
              <th style="text-align: right;">Prix Unitaire</th>
              <th style="text-align: right;">Total</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(item => `
              <tr>
                <td>${item.item ? item.item.title : 'Produit'}</td>
                <td style="text-align: center;">${item.qty}</td>
                <td style="text-align: right;">${(item.price / item.qty).toLocaleString()} DA</td>
                <td style="text-align: right;">${item.price.toLocaleString()} DA</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <div class="totals">
          <div>Frais de livraison (${order.city}): <strong>${(order.shippingFee || 0).toLocaleString()} DA</strong></div>
          <div class="grand-total">Total TTC: ${(order.totalWithShipping || 0).toLocaleString()} DA</div>
        </div>

        <div class="no-print">
          <button class="btn-print" onclick="window.print()">Imprimer la Facture / Télécharger PDF</button>
        </div>
      </body>
      </html>
    `);
  } catch(e) {
    console.error('Invoice error:', e);
    res.status(500).send('Erreur lors de la génération de la facture');
  }
});

// Confirmation page (GET)
router.get("/order/deliver/:orderId", async (req, res) => {
  if (!safeCompare(req.query.secret, process.env.DELIVERY_SECRET)) {
    return res.status(403).send("Access denied");
  }
  if (!isValidObjectId(req.params.orderId)) {
    return res.status(404).send("Order not found");
  }

  try {
    const order = await Order.findById(req.params.orderId);

    if (!order) {
      return res.status(404).send("Order not found");
    }

    if (order.status === "delivered") {
      return res.send("<h2>✅ Order already delivered.</h2>");
    }

    res.send(`
      <html>
        <head>
          <title>Confirm Delivery</title>
        </head>
        <body style="font-family:Arial;text-align:center;padding-top:80px">
          <h2>Confirm delivery?</h2>

          <p>Order: ${order._id}</p>

          <form method="POST" action="/order/deliver/${order._id}?secret=${req.query.secret}">
            <button
              style="
                background:#28a745;
                color:white;
                padding:15px 35px;
                border:none;
                border-radius:8px;
                font-size:18px;
                cursor:pointer;
              ">
              ✅ Mark as Delivered
            </button>
          </form>
        </body>
      </html>
    `);

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Actually deliver the order (POST)
router.post("/order/deliver/:orderId", async (req, res) => {

  if (!safeCompare(req.query.secret, process.env.DELIVERY_SECRET)) {
    return res.status(403).send("Access denied");
  }
  if (!isValidObjectId(req.params.orderId)) {
    return res.status(404).send("Order not found");
  }

  try {

    const order = await Order.findById(req.params.orderId);

    if (!order) {
      return res.status(404).send("Order not found");
    }

    if (order.status === "delivered") {
      return res.send("Order already delivered.");
    }

    await order.updateStatus(
      "delivered",
      "Manual delivery confirmation",
      "admin"
    );


    await sendPurchaseForDeliveredCOD(order);

    res.send("<h2>✅ Delivery confirmed.<br>Purchase event sent.</h2>");

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }

});
// ===== OTHER ROUTES - NO CAPI NEEDED =====
router.get('/shipping-fee/:wilaya', (req,res) => res.status(404).json({error:'Use new shipping logic'}));
router.post('/update-cart/:id', (req,res) => { let cart=new Cart(req.session.cart||{}); let newQty=parseInt(req.body.quantity); if(newQty>0) cart.update(req.params.id,newQty); req.session.cart=cart; res.redirect('/shop'); });
router.post('/subscribe', async (req,res) => {
  const email=req.body.email; if(!email){ req.flash('error','Email required'); return res.redirect('/'); }
  try{ const newEmail = new Newsletter({email}); await newEmail.save(); let transporter=nodemailer.createTransport({service:'gmail',auth:{user:process.env.EMAIL_USER,pass:process.env.EMAIL_PASS}}); await transporter.sendMail({from:`"Paintello" <${process.env.EMAIL_USER}>`,to:email,subject:'Welcome',html:'<p>Thank you for subscribing!</p>'}); req.flash('success','Subscribed'); res.redirect('/'); }catch(e){ console.error(e); req.flash('error','Error'); res.redirect('/'); }
});

// ===== CONTACT & TRACK - FIXED =====
router.get("/contact", async (req,res) => {
  try{
    const eventIdPageView=generateEventId(); const userData=getCleanUserData(req);
    if(userData){ setFbcCookieIfNeeded(req,res,userData); sendFacebookCAPIEvent({eventName:"PageView",eventId:eventIdPageView,userData,eventSourceUrl:getEventSourceUrl(req),customData:{},testEventCode:getTestCode(req)}).catch(()=>{}); console.log("✅ Contact PageView queued"); }
    else console.log("🤖 Bot detected – Contact PageView skipped");
    res.render("event/contact",{req,metaEventIdPageView:eventIdPageView,user:req.user});
  }catch(e){ res.status(500).send("Error"); }
});

router.get("/track-login", async (req,res) => {
  try{
    const eventIdPageView=generateEventId(); const userData=getCleanUserData(req);
    if(userData){ setFbcCookieIfNeeded(req,res,userData); sendFacebookCAPIEvent({eventName:"PageView",eventId:eventIdPageView,userData,eventSourceUrl:getEventSourceUrl(req),customData:{},testEventCode:getTestCode(req)}).catch(()=>{}); }
    const getStatusText=s=>({pending:'En Attente',confirmed:'Confirmée',processing:'En Préparation',ready_for_pickup:'Prête à Expédier',shipped:'Expédiée',out_for_delivery:'En Livraison',delivered:'Livrée',cancelled:'Annulée',refunded:'Remboursée',on_hold:'En Attente'}[s]||s);
    const getReturnStatusText=s=>({none:'Aucun',requested:'Demandé',approved:'Approuvé',rejected:'Rejeté',processing:'En Cours',completed:'Terminé'}[s]||s);
    const getPaymentStatusText=s=>({pending:'En Attente',paid:'Payé',failed:'Échoué',refunded:'Remboursé',partially_refunded:'Partiellement Remboursé'}[s]||'En Attente');
    res.render("event/track-login",{error:req.flash('error')[0],success:req.flash('success')[0],getStatusText,getReturnStatusText,getPaymentStatusText,req,metaEventIdPageView:eventIdPageView,user:req.user});
  }catch(e){ res.status(500).send("Error"); }
});

router.post('/track-login', async (req,res) => {
  try{
    let {numero}=req.body; if(!/^0[5-7][0-9]{8}$/.test(numero)){ req.flash('error','Numéro invalide'); return res.redirect('/track-login'); }
    const eventIdPageView=generateEventId(); const userData=getCleanUserData(req);
    if(userData){ setFbcCookieIfNeeded(req,res,userData); sendFacebookCAPIEvent({eventName:"PageView",eventId:eventIdPageView,userData,eventSourceUrl:`https://${req.get("host")}/track-order`,customData:{},testEventCode:getTestCode(req)}).catch(()=>{}); sendFacebookCAPIEvent({eventName:"Search",eventId:generateEventId(),userData,customData:{search_string:"order_tracking",content_type:"order",value:0,currency:"DZD"},eventSourceUrl:`https://${req.get("host")}/track-order`,testEventCode:getTestCode(req)}).catch(()=>{}); }
    const orders = await Order.findByAnyPhoneFormat(numero);
    const orderCount=orders.length;
    const getStatusText=s=>({pending:'En Attente',confirmed:'Confirmée',processing:'En Préparation',ready_for_pickup:'Prête à Expédier',shipped:'Expédiée',out_for_delivery:'En Livraison',delivered:'Livrée',cancelled:'Annulée',refunded:'Remboursée',on_hold:'En Attente'}[s]||s);
    const getReturnStatusText=s=>({none:'Aucun',requested:'Demandé',approved:'Approuvé',rejected:'Rejeté',processing:'En Cours',completed:'Terminé'}[s]||s);
    const getPaymentStatusText=s=>({pending:'En Attente',paid:'Payé',failed:'Échoué',refunded:'Remboursé',partially_refunded:'Partiellement Remboursé'}[s]||'En Attente');
    const getProgressWidth=s=>({pending:10,confirmed:30,processing:50,ready_for_pickup:60,shipped:75,out_for_delivery:90,delivered:100,cancelled:100,refunded:100,on_hold:10}[s]||10);
    const getTimelineStatus=(curr,check)=>{ const order=['pending','confirmed','processing','shipped','delivered']; const ci=order.indexOf(curr), chi=order.indexOf(check); if(chi<ci) return 'completed'; if(chi===ci) return 'active'; return ''; };
    if(orderCount===0){ req.flash('error','لا توجد طلبات'); return res.render('event/track-order',{orders:[],phoneNumber:numero,error:req.flash('error')[0],getStatusText,orderCount:0,getReturnStatusText,getPaymentStatusText,getProgressWidth,getTimelineStatus,req,metaEventIdPageView:eventIdPageView,user:{numero}}); }
    if(userData && orderCount>0){ sendFacebookCAPIEvent({eventName:"Lead",eventId:generateEventId(),userData,customData:{content_name:"Order Found",content_type:"order_status",value:orders.length,currency:"DZD"},eventSourceUrl:`https://${req.get("host")}/track-order`,testEventCode:getTestCode(req)}).catch(()=>{}); }
    req.session.trackingUser=numero;
    res.render('event/track-order',{orders,phoneNumber:numero,suggestAccountCreation:orderCount>0,success:req.flash('success')[0],orderCount,error:req.flash('error')[0],getStatusText,getReturnStatusText,getPaymentStatusText,getProgressWidth,getTimelineStatus,req,metaEventIdPageView:eventIdPageView,user:{numero}});
  }catch(err){ console.error(err); req.flash('error','خطأ'); res.redirect('/track-login'); }
});

router.get('/track-order', async (req,res) => {
  if(!req.session.trackingUser) return res.redirect('/track-login');
  try{
    const eventIdPageView=generateEventId(); const userData=getCleanUserData(req);
    if(userData){ setFbcCookieIfNeeded(req,res,userData); sendFacebookCAPIEvent({eventName:"PageView",eventId:eventIdPageView,userData,eventSourceUrl:getEventSourceUrl(req),customData:{},testEventCode:getTestCode(req)}).catch(()=>{}); }
    const orders = await Order.find({numero:req.session.trackingUser}).sort({createdAt:-1}).populate({path:'returnRequest',options:{strictPopulate:false}});
    const getStatusText=s=>({pending:'En Attente',confirmed:'Confirmée',processing:'En Préparation',ready_for_pickup:'Prête à Expédier',shipped:'Expédiée',out_for_delivery:'En Livraison',delivered:'Livrée',cancelled:'Annulée',refunded:'Remboursée',on_hold:'En Attente'}[s]||s);
    const getReturnStatusText=s=>({none:'Aucun',requested:'Demandé',approved:'Approuvé',rejected:'Rejeté',processing:'En Cours',completed:'Terminé'}[s]||s);
    const getPaymentStatusText=s=>({pending:'En Attente',paid:'Payé',failed:'Échoué',refunded:'Remboursé',partially_refunded:'Partiellement Remboursé'}[s]||'En Attente');
    const getProgressWidth=s=>({pending:10,confirmed:30,processing:50,ready_for_pickup:60,shipped:75,out_for_delivery:90,delivered:100,cancelled:100,refunded:100,on_hold:10}[s]||10);
    const getTimelineStatus=(curr,check)=>{ const order=['pending','confirmed','processing','shipped','delivered']; const ci=order.indexOf(curr), chi=order.indexOf(check); if(chi<ci) return 'completed'; if(chi===ci) return 'active'; return ''; };
    res.render('event/track-order',{orders,phoneNumber:req.session.trackingUser,success:req.flash('success')[0],error:req.flash('error')[0],getStatusText,getReturnStatusText,getPaymentStatusText,getProgressWidth,getTimelineStatus,req,metaEventIdPageView:eventIdPageView,user:{numero:req.session.trackingUser}});
  }catch(err){ console.error(err); req.flash('error','Error'); res.redirect('/track-login'); }
});

// ===== PRODUCTHOME - ALREADY FIXED, KEEPING IT =====
// Lighting category page - lists all lighting products (both vase-based lamps
// via baseVaseId and standalone lighting designs), grid style matching the rest
// of the site.
router.get("/eclairage", async (req, res) => {
  try {
    const lightingProducts = await Producthome.find({ type: "lighting", disponible: true })
      .sort({ createdAt: -1 })
      .lean();

    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req, res, userData);
      sendFacebookCAPIEvent({ eventName: "PageView", eventId: eventIdPageView, userData, eventSourceUrl: getEventSourceUrl(req), customData: {}, testEventCode: getTestCode(req) }).catch(() => {});
    }

    res.render("event/lighting", {
      lightingProducts,
      req,
      metaEventIdPageView: eventIdPageView,
      user: req.user,
      login: req.isAuthenticated()
    });
  } catch (error) {
    console.error("❌ Lighting page error:", error);
    res.status(500).send("Server Error");
  }
});

router.get("/producthome/:id", async (req, res) => {
  try {
    const rawId = req.params.id; const cleanId = rawId.replace(/\.\w+$/, '');
    if (!isValidObjectId(cleanId)) return res.status(404).send("Product not found");
    const producthome = await Producthome.findById(cleanId).lean();
    if (!producthome) return res.status(404).send("Product not found");
    const reviews = await Review.find({ productId: producthome._id, published: true }).sort({ createdAt: -1 }).lean();
    const avgRating = reviews.length ? (reviews.reduce((s, r) => s + r.rating, 0) / reviews.length) : 0;
    const eventIdPageView = generateEventId(); const eventIdView = generateEventId(); const eventIdCart = generateEventId();
    const userData = getCleanUserData(req);
    if (userData) {
      setFbcCookieIfNeeded(req,res,userData);
      const productIdStr = producthome._id.toString(); const testCode = getTestCode(req);
      sendFacebookCAPIEvent({ eventName:"PageView", eventId:eventIdPageView, userData, eventSourceUrl:getEventSourceUrl(req), customData:{}, testEventCode:testCode }).catch(()=>{});
      const phCategory = producthome.type || 'vases';
      sendFacebookCAPIEvent({ eventName:"ViewContent", eventId:eventIdView, userData, customData:{ content_name:producthome.title, content_category:phCategory, content_ids:[productIdStr], contents:[{id:productIdStr, quantity:1, item_price:Number(producthome.price)}], content_type:"product", value:Number(producthome.price), currency:"DZD" }, eventSourceUrl:getEventSourceUrl(req), testEventCode:testCode }).catch(()=>{});
      console.log("✅ PageView + ViewContent queued");
    } else { console.log("🤖 Bot detected – ViewContent skipped", getBotClassification(req)?.botType); }
    // Fetch a bounded pool of candidates once, then do all matching in JS below rather
    // than as separate MongoDB query conditions. Two reasons: (1) `disponible` casting
    // already bit us once (see isAvailable() above); (2) `type` is schema-normalized
    // (lowercase/trim) only when saved *through* Mongoose - a document pasted directly
    // into Atlas keeps whatever casing/whitespace it was given, so a strict `{ type:
    // producthome.type }` query can silently miss real siblings over something as small
    // as "Draped_Wedding_Dress" vs "draped_wedding_dress ". Normalizing on both sides
    // in JS avoids that regardless of how a document was written.
    const [candidatePool, paintellos] = await Promise.all([
      Producthome.find({ _id: { $ne: producthome._id } }).sort({ createdAt: -1 }).limit(200).lean(),
      Paintello.find({}).limit(20).lean()
    ]);
    const availablePool = candidatePool.filter(isAvailable);
    const normalizeType = t => (t || '').toString().trim().toLowerCase();
    const currentType = normalizeType(producthome.type);

    let finalRelated = currentType
      ? availablePool.filter(p => normalizeType(p.type) === currentType).slice(0, 8)
      : [];
    // Fallback 1: overlap on title words - runs even when `type` isn't set on this
    // product, and tries a few words, not just the first, for better odds of finding
    // a match. Words are regex-escaped so a title containing ( ) + . etc. can't
    // produce an invalid regex and crash the page.
    if (finalRelated.length < 4) {
      const usedIds = new Set(finalRelated.map(p => String(p._id)));
      const titleWords = (producthome.title || '').split(' ').filter(w => w.length > 3);
      if (titleWords.length > 0) {
        const wordRegexes = titleWords.slice(0, 3).map(w => new RegExp(escapeRegex(w), 'i'));
        const matches = availablePool.filter(p =>
          !usedIds.has(String(p._id)) && wordRegexes.some(r => r.test(p.title || ''))
        );
        finalRelated = [...finalRelated, ...matches.slice(0, 8 - finalRelated.length)];
      }
    }
    // Fallback 2: still nothing (no shared type, no title overlap) - show any other
    // available product rather than leaving the cross-sell section empty/hidden.
    if (finalRelated.length === 0) {
      finalRelated = availablePool.slice(0, 4);
    }
    req.session.preGeneratedEventIds = { cart:eventIdCart, view:eventIdView, page:eventIdPageView, testCode:getTestCode(req) };
    const has3DModel = !!producthome.stlFile;
    const defaultColor = producthome.model3D?.defaultColor?.startsWith("#") ? producthome.model3D.defaultColor : `#${producthome.model3D?.defaultColor || "8CAAE6"}`;
    res.render("event/producthome", { producthome, relatedProducts:finalRelated, paintellos, reviews, avgRating, req, metaEventIdView:eventIdView, metaEventIdCart:eventIdCart, metaEventIdPageView:eventIdPageView, has3DModel, model3DSettings:{enabled:has3DModel,stlFile:producthome.stlFile,autoRotate:producthome.model3D?.autoRotate??true,defaultColor}, user:req.user, login:req.isAuthenticated() });
  } catch (error) { console.error(error); res.status(500).send("Server Error"); }
});

router.get("/add-to-cart-producthome/:id", async (req, res) => {
  try {
    const rawId=req.params.id; const cleanId=rawId.replace(/\.\w+$/,''); const quantity=clampQuantity(req.query.qty); const secondProductId=req.query.second; const redirectTo=req.query.redirect;
    if (!isValidObjectId(cleanId)) return res.status(404).send("Product not found");
    if (secondProductId && !isValidObjectId(secondProductId)) return res.status(404).send("Second product not found");
    const cart=new Cart(req.session.cart||{}); const producthome=await Producthome.findById(cleanId).lean(); if(!producthome) return res.status(404).send("Product not found");
    for(let i=0;i<quantity;i++) cart.add(producthome, producthome._id.toString());
    let secondProduct=null, secondProductDiscountedPrice=0; const DISCOUNT_RATE=0.10;
    if(secondProductId){ secondProduct=await Producthome.findById(secondProductId).lean(); if(secondProduct){ const discountedId=secondProductId===cleanId?`${secondProductId}-discounted`:secondProductId; cart.addDiscounted(secondProduct,discountedId,DISCOUNT_RATE,cleanId); secondProductDiscountedPrice=secondProduct.price*(1-DISCOUNT_RATE); } }
    req.session.cart=cart;
    const userData=getCleanUserData(req); if(!userData){ console.log("🤖 Bot detected – AddToCart skipped"); return res.redirect(redirectTo==="checkout"?"/checkout":"/shop"); }
    const eventIds=req.session.preGeneratedEventIds||{}; const eventIdCart=eventIds.cart||generateEventId(); const testCode=getTestCode(req);
    const mainIdStr=producthome._id.toString(); const contents=[{id:mainIdStr,quantity,item_price:Number(producthome.price)}]; let totalValue=Number(producthome.price)*quantity;
    if(secondProduct){ const secondIdStr=secondProduct._id.toString(); if(secondIdStr===mainIdStr){ contents[0].quantity+=1; contents.push({id:`${secondIdStr}-discount`,quantity:1,item_price:secondProductDiscountedPrice}); } else { contents.push({id:secondIdStr,quantity:1,item_price:secondProductDiscountedPrice}); } totalValue+=secondProductDiscountedPrice; }
    const phCategory = producthome.type || 'vases';
    await sendFacebookCAPIEvent({ eventName:"AddToCart", eventId:eventIdCart, userData, customData:{ content_name:producthome.title, content_category:phCategory, content_ids:[...new Set(contents.map(c=>c.id.replace('-discount','').replace('-discounted','')))], contents, content_type:"product", value:totalValue, currency:"DZD" }, eventSourceUrl:getEventSourceUrl(req), testEventCode:testCode });
    console.log("✅ AddToCart sent"); if(req.session.preGeneratedEventIds) delete req.session.preGeneratedEventIds.cart;
    res.redirect(redirectTo==="checkout"?"/checkout":"/shop");
  } catch(error){ console.error(error); res.status(500).send("Server Error"); }
});

router.get('/paintello', async (req,res) => {
  try{
    const selectedCategory = (req.query.category || 'all').toLowerCase().trim();
    const paintellos = await Paintello.find({}).lean();

    const categories = ['all', 'vases', 'lampshades'];

    const eventIdPageView=generateEventId(); const userData=getCleanUserData(req);
    if(userData){ setFbcCookieIfNeeded(req,res,userData); sendFacebookCAPIEvent({eventName:"PageView",eventId:eventIdPageView,userData,eventSourceUrl:getEventSourceUrl(req),customData:{},testEventCode:getTestCode(req)}).catch(()=>{}); console.log("✅ Paintello PageView queued"); }
    else console.log("🤖 Bot detected – Paintello PageView skipped");
    res.render('event/paintellohome',{paintellos, categories, selectedCategory, req, metaEventIdPageView:eventIdPageView, user:req.user});
  }catch(err){ res.status(500).send('Error'); }
});

router.get('/webhook', (req,res) => {
  const VERIFY_TOKEN = process.env.WEBHOOK_VERIFY_TOKEN;
  const mode=req.query["hub.mode"]; const token=req.query["hub.verify_token"]; const challenge=req.query["hub.challenge"];
  if(mode==="subscribe" && safeCompare(token, VERIFY_TOKEN)){ console.log("✅ Webhook verified"); return res.status(200).send(challenge); } else return res.sendStatus(403);
});

// Verifies the request really came from Meta using the X-Hub-Signature-256 header (HMAC-SHA256 of the raw body, keyed with your app secret).
// Requires the raw request body - if you use express.json() globally, capture the raw body via a verify() callback and attach it as req.rawBody.
function isValidMetaSignature(req) {
  const signature = req.get('x-hub-signature-256');
  if (!signature || !req.rawBody || !process.env.META_APP_SECRET) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', process.env.META_APP_SECRET).update(req.rawBody).digest('hex');
  return safeCompare(signature, expected);
}

router.post('/webhook', async (req,res) => {
  try{
    if (!isValidMetaSignature(req)) {
      console.warn('🚫 Webhook signature invalid - rejecting');
      return res.sendStatus(403);
    }
    const entry=req.body.entry?.[0]; const changes=entry?.changes?.[0]; const messages=changes?.value?.messages?.[0];
    if(!messages) return res.sendStatus(200);
    const from=messages.from; const customerName=changes?.value?.contacts?.[0]?.profile?.name||from;
    const name=customerName; const numero=from.startsWith('213')?'0'+from.slice(3):from;

    // WhatsApp sends a completely different payload shape per message type - only
    // 'text' messages have a .text.body field. Media types (image/video/audio/
    // document/sticker) carry their content as a media ID under messages[type].id,
    // which has to be resolved separately via the Graph API (see the media proxy
    // route) - the ID itself isn't a URL and can't be displayed directly.
    const MEDIA_TYPES = ['image', 'video', 'audio', 'document', 'sticker'];
    let text, mediaId = null, mediaType = null;

    if (messages.type === 'text') {
      text = messages.text?.body?.trim() || '[Message vide]';
    } else if (MEDIA_TYPES.includes(messages.type)) {
      mediaType = messages.type;
      mediaId = messages[messages.type]?.id || null;
      const captionMap = { image: 'Photo', video: 'Vidéo', audio: 'Message vocal / audio', document: 'Document', sticker: 'Sticker' };
      text = `[${captionMap[messages.type] || messages.type}]`;
    } else {
      text = `[Message non pris en charge: ${messages.type}]`;
    }

    WhatsAppMessage.create({ phone: from, customerName: name, direction: 'in', text, mediaId, mediaType })
      .catch((e) => console.error('WhatsAppMessage save error:', e.message));

    sendClientReplyEmail({name,numero,response:text}).catch((e)=>console.error('sendClientReplyEmail error:', e.message));
    sendTelegramMessage(`💬 <b>Message WhatsApp</b>\n👤 De: ${name} (${numero})\n📝 Texte: ${text}`).catch((e)=>console.error('sendTelegramMessage error:', e.message));
    return res.sendStatus(200);
  }catch(err){ console.error(err); return res.sendStatus(500); }
});

router.post('/validate-coupon', async (req, res) => {
  try {
    const { code, cartTotal } = req.body;
    if (!code) {
      return res.status(400).json({ valid: false, message: 'Code promo requis.' });
    }

    const coupon = await Coupon.findOne({ code: code.trim().toUpperCase(), active: true });
    if (!coupon) {
      return res.status(404).json({ valid: false, message: 'Code promo invalide ou expiré.' });
    }

    const numericTotal = parseFloat(cartTotal) || 0;
    if (!coupon.isValid(numericTotal)) {
      if (coupon.minOrderAmount > numericTotal) {
        return res.status(400).json({ valid: false, message: `Montant minimum de commande: ${coupon.minOrderAmount} DA.` });
      }
      return res.status(400).json({ valid: false, message: 'Code promo non applicable.' });
    }

    let discountAmount = 0;
    if (coupon.discountType === 'percent') {
      discountAmount = (numericTotal * coupon.discountValue) / 100;
    } else {
      discountAmount = Math.min(numericTotal, coupon.discountValue);
    }

    res.json({
      valid: true,
      code: coupon.code,
      discountType: coupon.discountType,
      discountValue: coupon.discountValue,
      discountAmount: Number(discountAmount.toFixed(2)),
      message: `Code promo ${coupon.code} appliqué !`
    });

  } catch (err) {
    console.error('❌ Validate coupon error:', err);
    res.status(500).json({ valid: false, message: 'Erreur lors de la vérification du code.' });
  }
});

router.post('/notify-me/:productId', async (req,res) => {
  try{
    const {productId}=req.params; const {email,phone}=req.body;
    if(!isValidObjectId(productId)) return res.status(404).json({success:false,message:'Produit non trouvé'});
    const emailRegex=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if(!emailRegex.test(email)) return res.status(400).json({success:false,message:'Format d\'email invalide'});
    const product=await Producthome.findById(productId); if(!product) return res.status(404).json({success:false,message:'Produit non trouvé'});
    const existing=await Notification.findOne({productId,email}); if(existing) return res.json({success:true,message:'Déjà inscrit'});
    const notification=new Notification({productId,email,phone:phone||null,notified:false,createdAt:new Date()}); await notification.save();
    res.json({success:true,message:'Vous serez notifié'});
  }catch(e){ console.error(e); res.status(500).json({success:false,message:'Erreur serveur'}); }
});

// Meta Advantage+ Catalog Dynamic XML Product Feed
router.get(['/catalog.xml', '/feed/facebook.xml'], async (req, res) => {
  try {
    const host = req.get('host') || 'paintello.uk';
    const baseUrl = `https://${host}`;

    const [homeProducts, paintelloProducts] = await Promise.all([
      Producthome.find({}).lean(),
      Paintello.find({}).lean()
    ]);

    function escapeXml(unsafe) {
      return (unsafe || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
    }

    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">
  <channel>
    <title>Paintello Home Catalog Feed</title>
    <link>${baseUrl}</link>
    <description>Meta Advantage+ XML Product Catalog Feed for Paintello</description>
`;

    homeProducts.forEach(p => {
      const pId = p._id.toString();
      const title = escapeXml(p.title || 'Paintello Product');
      const description = escapeXml(p.description || p.subtitle || p.title);
      const link = `${baseUrl}/producthome/${pId}`;
      const img = p.image && p.image[0] ? (p.image[0].startsWith('http') ? p.image[0] : `${baseUrl}${p.image[0]}`) : `${baseUrl}/img/placeholder.png`;
      const price = `${Number(p.price || 0).toFixed(2)} DZD`;
      const inStock = typeof p.stock !== 'undefined' ? p.stock > 0 : (p.disponible !== false);
      const availability = inStock ? 'in stock' : 'out of stock';

      xml += `    <item>
      <g:id>${pId}</g:id>
      <g:title>${title}</g:title>
      <g:description>${description}</g:description>
      <g:link>${escapeXml(link)}</g:link>
      <g:image_link>${escapeXml(img)}</g:image_link>
      <g:brand>Paintello</g:brand>
      <g:condition>new</g:condition>
      <g:availability>${availability}</g:availability>
      <g:price>${price}</g:price>
      <g:google_product_category>Home &amp; Garden &gt; Decor</g:google_product_category>
    </item>\n`;
    });

    paintelloProducts.forEach(p => {
      const pId = p._id.toString();
      const title = escapeXml(p.title || 'Paintello Art');
      const description = escapeXml(p.title);
      const link = p.href ? (p.href.startsWith('http') ? p.href : `${baseUrl}${p.href}`) : `${baseUrl}/producthome/${pId}`;
      const img = p.image && p.image[0] ? (p.image[0].startsWith('http') ? p.image[0] : `${baseUrl}${p.image[0]}`) : `${baseUrl}/img/placeholder.png`;
      const price = `${Number(p.price || 0).toFixed(2)} DZD`;
      const inStock = typeof p.stock !== 'undefined' ? p.stock > 0 : (p.disponible !== false);
      const availability = inStock ? 'in stock' : 'out of stock';

      xml += `    <item>
      <g:id>${pId}</g:id>
      <g:title>${title}</g:title>
      <g:description>${description}</g:description>
      <g:link>${escapeXml(link)}</g:link>
      <g:image_link>${escapeXml(img)}</g:image_link>
      <g:brand>Paintello</g:brand>
      <g:condition>new</g:condition>
      <g:availability>${availability}</g:availability>
      <g:price>${price}</g:price>
      <g:google_product_category>Home &amp; Garden &gt; Decor</g:google_product_category>
    </item>\n`;
    });

    xml += `  </channel>\n</rss>`;

    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.send(xml);

  } catch (err) {
    console.error('❌ Catalog Feed error:', err);
    res.status(500).send('Catalog Error');
  }
});

module.exports = router;
