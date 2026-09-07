var express = require('express');
var router = express.Router();
var csrf = require('csurf');
var passport = require('passport');

const middleware = require('../middleware');
const getCleanUserData = require('../utils/userData');
const sendFacebookCAPIEvent = require('../services/facebookCapi');
const Cart = require('../models/cart');
const Order = require('../models/order');
var header = require('../models/header');
const WhatsAppMessage = require('../models/whatsappMessage');
const Review = require('../models/review');
const Producthome = require('../models/producthome');
const Paintello = require('../models/paintello');
const axios = require('axios');

// protect routes using csrf
var csrfProtection = csrf();
router.use(csrfProtection);

// UUID v4 generator function
function generateEventId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// ==========================================
// 1. PROFILE ROUTE (Optimized for your View)
// ==========================================
router.get('/profile', middleware.isLoggedIn, async function(req, res, next) {
  try {
    const headers = await header.find({});
    
    // 1. Get User Stats and Orders
    // This finds orders where (user matches ID) OR (phone matches user phone)
    const orders = await Order.findUserCompleteHistory(req.user._id, req.user.numero);
    
    // 2. Track PageView
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);

    if (userData) {
      await sendFacebookCAPIEvent({
        eventName: "PageView",
        eventId: eventIdPageView,
        userData,
        eventSourceUrl: `https://${req.get("host")}${req.originalUrl}`,
        testEventCode: req.query.test_event_code || process.env.FB_TEST_EVENT_CODE
      });
    }

    // 3. Process Orders for Display (Calculate stats)
    let totalSpent = 0;
    let totalItems = 0;
    let deliveredOrders = 0;
    let deliveredItems = 0;
    
    const processedOrders = orders.map(order => {
      // Re-hydrate cart if needed for display
      const cart = new Cart(order.cart);
      order.items = cart.generateArray();

      // Ensure virtuals (like statusDisplay) are available
      // Note: Mongoose virtuals are usually auto-available in templates, 
      // but calculations below need raw data
      
      const orderTotal = order.totalWithShipping || 0;
      const orderQty = order.cart.totalQty || 0;

      totalSpent += orderTotal;
      totalItems += orderQty;

      if (order.status === 'delivered') {
        deliveredOrders++;
        deliveredItems += orderQty;
      }
      
      return order;
    });

    // 4. Prepare User Stats Object
    const userStats = {
      totalOrders: orders.length,
      totalSpent: totalSpent,
      totalItems: totalItems,
      deliveredOrders: deliveredOrders,
      deliveredItems: deliveredItems,
      memberSince: req.user.createdAt,
      statusCounts: {
        pending: orders.filter(o => o.status === 'pending').length,
        confirmed: orders.filter(o => o.status === 'confirmed').length,
        processing: orders.filter(o => o.status === 'processing').length,
        shipped: orders.filter(o => o.status === 'shipped').length,
        delivered: orders.filter(o => o.status === 'delivered').length,
        cancelled: orders.filter(o => o.status === 'cancelled').length
      }
    };

    // 5. Render View
    res.render('user/profile', {
      orders: processedOrders,
      headers: headers,
      req: req,
      metaEventIdPageView: eventIdPageView,
      user: req.user,
      registrationEventId: req.session.completeRegistrationEventId || null,
      userStats: userStats,
      // Pass helper functions for the view if your logic relies on them inside EJS
      getStatusText: (s) => s, 
      getProgressWidth: (s) => 10
    });

  } catch (err) {
    console.error("❌ Error loading user profile:", err);
    res.redirect('/');
  }
});

// Logout Route
router.get('/logout', middleware.isLoggedIn, function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/user/signup');
  });
});

// ⚠️ requireAdmin est un PLACEHOLDER — à ajuster une fois que j'ai vu ton models/user.js.
// Par défaut ça vérifie req.user.isAdmin, ce qui ne bloquera RIEN si ce champ n'existe pas.
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user && req.user.isAdmin) return next();
  return res.status(403).send("Accès refusé");
}

const WINDOW_MS = 24 * 60 * 60 * 1000;

// Liste des conversations (une ligne par numéro, dernier message en premier)
router.get('/admin/whatsapp', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const conversations = await WhatsAppMessage.aggregate([
      { $sort: { createdAt: -1 } },
      { $group: {
          _id: '$phone',
          customerName: { $first: '$customerName' },
          lastText: { $first: '$text' },
          lastDirection: { $first: '$direction' },
          lastAt: { $first: '$createdAt' },
          unread: { $sum: { $cond: [{ $and: [{ $eq: ['$direction','in'] }, { $eq: ['$read', false] }] }, 1, 0] } }
      }},
      { $sort: { lastAt: -1 } }
    ]);
    res.render('admin/whatsapp-inbox', { conversations, user: req.user });
  } catch (err) {
    console.error("❌ WhatsApp inbox error:", err);
    res.status(500).send("Server Error");
  }
});

// Thread d'une conversation + formulaire de réponse
router.get('/admin/whatsapp/:phone', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const phone = req.params.phone;
    const messages = await WhatsAppMessage.find({ phone }).sort({ createdAt: 1 }).lean();
    if (messages.length === 0) return res.status(404).send("Conversation introuvable");

    await WhatsAppMessage.updateMany({ phone, direction: 'in', read: false }, { $set: { read: true } });

    const lastInbound = [...messages].reverse().find(m => m.direction === 'in');
    const withinWindow = lastInbound ? (Date.now() - new Date(lastInbound.createdAt).getTime()) < WINDOW_MS : false;

    res.render('admin/whatsapp-thread', {
      phone,
      customerName: messages[messages.length - 1].customerName || phone,
      messages,
      withinWindow,
      csrfToken: req.csrfToken(),
      flashErrors: req.flash('error'),
      user: req.user
    });
  } catch (err) {
    console.error("❌ WhatsApp thread error:", err);
    res.status(500).send("Server Error");
  }
});

// Envoi de la réponse
router.post('/admin/whatsapp/:phone/reply', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const phone = req.params.phone;
    const text = (req.body.text || '').trim();
    if (!text) {
      req.flash('error', 'Message vide.');
      return res.redirect(`/user/admin/whatsapp/${phone}`);
    }

    await axios.post(`https://graph.facebook.com/v19.0/${process.env.META_PHONE_ID}/messages`, {
      messaging_product: "whatsapp",
      to: phone,
      type: "text",
      text: { body: text }
    }, {
      headers: { Authorization: `Bearer ${process.env.META_WA_TOKEN}`, 'Content-Type': 'application/json' }
    });

    await WhatsAppMessage.create({ phone, direction: 'out', text });
    res.redirect(`/user/admin/whatsapp/${phone}`);
  } catch (err) {
    console.error("❌ WhatsApp reply error:", err.response?.data || err.message);
    // Cas le plus probable : la fenêtre de 24h est dépassée, WhatsApp refuse les messages libres
    req.flash('error', "Échec de l'envoi — le client n'a peut-être pas écrit depuis plus de 24h (WhatsApp bloque alors les messages libres, seuls les modèles pré-approuvés passent).");
    res.redirect(`/user/admin/whatsapp/${req.params.phone}`);
  }
});

// Sert une image/vidéo/document reçu par WhatsApp. L'ID stocké n'est pas une URL :
// il faut d'abord le résoudre auprès de Meta pour obtenir un lien de téléchargement
// temporaire, puis récupérer le fichier lui-même - les deux appels nécessitent le
// même token que pour l'envoi.
router.get('/admin/whatsapp/media/:mediaId', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const mediaId = req.params.mediaId;
    const metaRes = await axios.get(`https://graph.facebook.com/v19.0/${mediaId}`, {
      headers: { Authorization: `Bearer ${process.env.META_WA_TOKEN}` }
    });
    const { url, mime_type } = metaRes.data;
    if (!url) return res.status(404).send('Média introuvable');

    const fileRes = await axios.get(url, {
      headers: { Authorization: `Bearer ${process.env.META_WA_TOKEN}` },
      responseType: 'arraybuffer'
    });

    res.set('Content-Type', mime_type || 'application/octet-stream');
    res.set('Cache-Control', 'private, max-age=3600');
    res.send(fileRes.data);
  } catch (err) {
    console.error('❌ WhatsApp media proxy error:', err.response?.data || err.message);
    res.status(502).send('Impossible de récupérer le média');
  }
});

// ===================== PRODUCT CREATION =====================
router.get('/admin/products/new', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  res.render('admin/product-new', {
    csrfToken: req.csrfToken(),
    flashErrors: req.flash('error'),
    user: req.user
  });
});

router.post('/admin/products/new', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const { title, subtitle, price, buyPrice, stock, category, type, modelType, image, description } = req.body;

    if (!title || !price) {
      req.flash('error', 'Product title and price are required.');
      return res.redirect('/user/admin/products/new');
    }

    const imageArray = (image || '')
      .split('\n')
      .map(url => url.trim())
      .filter(Boolean);

    const numericPrice = parseFloat(price) || 0;
    const numericBuyPrice = parseFloat(buyPrice) || 0;
    const numericStock = parseInt(stock) >= 0 ? parseInt(stock) : 10;
    const isDisponible = numericStock > 0;

    if (modelType === 'Paintello') {
      await Paintello.create({
        title: title.trim(),
        price: numericPrice,
        buyPrice: numericBuyPrice,
        stock: numericStock,
        disponible: isDisponible,
        category: (category || 'vases').toLowerCase().trim(),
        type: (type || '').toLowerCase().trim(),
        image: imageArray,
        status: 'New'
      });
    } else {
      await Producthome.create({
        title: title.trim(),
        subtitle: subtitle ? subtitle.trim() : '',
        price: numericPrice,
        buyPrice: numericBuyPrice,
        stock: numericStock,
        type: (type || category || 'vases').toLowerCase().trim(),
        disponible: isDisponible,
        image: imageArray,
        description: description ? description.trim() : ''
      });
    }

    res.redirect('/user/admin/finance');
  } catch (err) {
    console.error('❌ Product creation error:', err);
    req.flash('error', 'Failed to create product.');
    res.redirect('/user/admin/products/new');
  }
});

// ===================== FINANCE DASHBOARD (COD ALGERIA SPECIFIC) =====================
router.get('/admin/finance', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const [allOrders, paintelloProds, homeProds] = await Promise.all([
      Order.find({}).sort({ createdAt: -1 }).lean(),
      Paintello.find({}).lean(),
      Producthome.find({}).lean()
    ]);

    const productSalesMap = {};
    const productDeliveredSalesMap = {};
    const productNameMap = {};
    const productBuyPriceMap = {};
    const productSellPriceMap = {};

    paintelloProds.forEach(p => {
      const id = p._id.toString();
      productNameMap[id] = p.title || 'Paintello Product';
      productBuyPriceMap[id] = Number(p.buyPrice) || 0;
      productSellPriceMap[id] = Number(p.price) || 0;
    });

    homeProds.forEach(p => {
      const id = p._id.toString();
      productNameMap[id] = p.title || 'Home Product';
      productBuyPriceMap[id] = Number(p.buyPrice) || 0;
      productSellPriceMap[id] = Number(p.price) || 0;
    });

    let deliveredRevenue = 0;
    let deliveredShipping = 0;
    let deliveredCost = 0;

    let pipelineRevenue = 0;
    let cancelledRevenue = 0;

    let totalOrdersCount = allOrders.length;
    let deliveredCount = 0;
    let pipelineCount = 0;
    let cancelledCount = 0;

    const wilayaMap = {};

    const pipelineStatuses = ['pending', 'confirmed', 'processing', 'ready_for_pickup', 'shipped', 'out_for_delivery', 'on_hold'];
    const cancelledStatuses = ['cancelled', 'refunded'];

    allOrders.forEach(order => {
      const status = order.status || 'pending';
      const cart = order.cart || {};
      const rawItems = cart.items || {};
      const itemsList = Array.isArray(rawItems) ? rawItems : Object.keys(rawItems).map(k => rawItems[k]);

      const shippingFee = Number(order.shippingFee) || 0;
      let orderProductRevenue = 0;
      let orderProductCost = 0;

      itemsList.forEach(itemObj => {
        if (!itemObj) return;
        const qty = itemObj.qty || 1;
        const item = itemObj.item || {};
        const itemId = (item._id || itemObj.id || '').toString();

        if (itemId) {
          productSalesMap[itemId] = (productSalesMap[itemId] || 0) + qty;
          if (item.title) productNameMap[itemId] = item.title;
        }

        const sellP = itemObj.unitPrice || item.price || productSellPriceMap[itemId] || 0;
        const buyP = productBuyPriceMap[itemId] || item.buyPrice || 0;

        orderProductRevenue += sellP * qty;
        orderProductCost += buyP * qty;

        if (status === 'delivered' && itemId) {
          productDeliveredSalesMap[itemId] = (productDeliveredSalesMap[itemId] || 0) + qty;
        }
      });

      const orderTotalWithShipping = Number(order.totalWithShipping) || (orderProductRevenue + shippingFee);

      if (status === 'delivered') {
        deliveredCount++;
        deliveredRevenue += orderTotalWithShipping;
        deliveredShipping += shippingFee;
        deliveredCost += orderProductCost;

        const wilaya = (order.city || order.commune || 'Inconnu').trim();
        if (!wilayaMap[wilaya]) {
          wilayaMap[wilaya] = { name: wilaya, deliveredOrders: 0, revenue: 0 };
        }
        wilayaMap[wilaya].deliveredOrders++;
        wilayaMap[wilaya].revenue += orderTotalWithShipping;

      } else if (pipelineStatuses.includes(status)) {
        pipelineCount++;
        pipelineRevenue += orderTotalWithShipping;
      } else if (cancelledStatuses.includes(status)) {
        cancelledCount++;
        cancelledRevenue += orderTotalWithShipping;
      }
    });

    const netRealizedProfit = deliveredRevenue - deliveredCost;
    const profitMargin = deliveredRevenue > 0 ? (netRealizedProfit / deliveredRevenue) * 100 : 0;

    const deliverySuccessRate = totalOrdersCount > 0 ? (deliveredCount / totalOrdersCount) * 100 : 0;
    const completedOrdersCount = deliveredCount + cancelledCount;
    const fulfillmentSuccessRate = completedOrdersCount > 0 ? (deliveredCount / completedOrdersCount) * 100 : 0;

    const wilayaPerformance = Object.values(wilayaMap)
      .sort((a, b) => b.revenue - a.revenue);

    const topProducts = Object.keys(productSalesMap)
      .map(id => ({
        id,
        name: productNameMap[id] || 'Produit',
        totalQty: productSalesMap[id],
        deliveredQty: productDeliveredSalesMap[id] || 0,
        sellPrice: productSellPriceMap[id] || 0,
        buyPrice: productBuyPriceMap[id] || 0
      }))
      .sort((a, b) => b.deliveredQty - a.deliveredQty)
      .slice(0, 10);

    const allProducts = [
      ...paintelloProds.map(p => ({ ...p, sourceModel: 'Paintello' })),
      ...homeProds.map(p => ({ ...p, sourceModel: 'Producthome' }))
    ];

    res.render('admin/finance', {
      metrics: {
        deliveredRevenue,
        deliveredShipping,
        deliveredCost,
        netRealizedProfit,
        profitMargin,
        pipelineRevenue,
        cancelledRevenue,
        totalOrdersCount,
        deliveredCount,
        pipelineCount,
        cancelledCount,
        deliverySuccessRate,
        fulfillmentSuccessRate
      },
      wilayaPerformance,
      topProducts,
      products: allProducts,
      productSalesMap,
      productDeliveredSalesMap,
      csrfToken: req.csrfToken(),
      flashErrors: req.flash('error'),
      user: req.user
    });

  } catch (err) {
    console.error('❌ Finance dashboard error:', err);
    res.status(500).send('Server Error');
  }
});

router.post('/admin/finance/update-prices', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    let { productId, sourceModel, buyPrice, sellPrice, stock } = req.body;

    if (!Array.isArray(productId)) {
      productId = productId ? [productId] : [];
      sourceModel = sourceModel ? [sourceModel] : [];
      buyPrice = buyPrice ? [buyPrice] : [];
      sellPrice = sellPrice ? [sellPrice] : [];
      stock = stock ? [stock] : [];
    }

    const updates = [];
    for (let i = 0; i < productId.length; i++) {
      const id = productId[i];
      const modelName = sourceModel[i];
      const bPrice = Math.max(0, parseFloat(buyPrice[i]) || 0);
      const sPrice = Math.max(0, parseFloat(sellPrice[i]) || 0);
      const stQty = Math.max(0, parseInt(stock[i]) || 0);
      const isAvailable = stQty > 0;

      if (modelName === 'Paintello') {
        updates.push(Paintello.findByIdAndUpdate(id, { buyPrice: bPrice, price: sPrice, stock: stQty, disponible: isAvailable }));
      } else if (modelName === 'Producthome') {
        updates.push(Producthome.findByIdAndUpdate(id, { buyPrice: bPrice, price: sPrice, stock: stQty, disponible: isAvailable }));
      }
    }

    await Promise.all(updates);
    res.redirect('/user/admin/finance');
  } catch (err) {
    console.error('❌ Update price error:', err);
    req.flash('error', 'Erreur lors de la mise à jour des prix et stocks.');
    res.redirect('/user/admin/finance');
  }
});

// ===================== AVIS CLIENTS =====================
// Liste + formulaire d'ajout (ajoutés manuellement par l'admin depuis de vrais
// échanges WhatsApp, donc pas de file de modération séparée - juste publié/masqué)
router.get('/admin/reviews', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const [reviews, products] = await Promise.all([
      Review.find({}).populate('productId', 'title').sort({ createdAt: -1 }).lean(),
      Producthome.find({}).select('title').sort({ title: 1 }).lean()
    ]);
    res.render('admin/reviews', { reviews, products, csrfToken: req.csrfToken(), flashErrors: req.flash('error'), user: req.user });
  } catch (err) {
    console.error('❌ Reviews list error:', err);
    res.status(500).send('Server Error');
  }
});

router.post('/admin/reviews', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const { productId, customerName, rating, comment, imageUrls } = req.body;
    if (!productId || !customerName?.trim() || !rating) {
      req.flash('error', 'Produit, nom du client et note sont obligatoires.');
      return res.redirect('/user/admin/reviews');
    }
    // One URL per line in the textarea - split, trim, and drop blank lines.
    const urls = (imageUrls || '')
      .split('\n')
      .map(u => u.trim())
      .filter(Boolean);
    await Review.create({
      productId,
      customerName: customerName.trim(),
      rating: Math.min(5, Math.max(1, parseInt(rating) || 5)),
      comment: (comment || '').trim(),
      imageUrls: urls,
    });
    res.redirect('/user/admin/reviews');
  } catch (err) {
    console.error('❌ Review create error:', err);
    req.flash('error', "Erreur lors de l'ajout de l'avis.");
    res.redirect('/user/admin/reviews');
  }
});

router.post('/admin/reviews/:id/toggle', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);
    if (review) { review.published = !review.published; await review.save(); }
    res.redirect('/user/admin/reviews');
  } catch (err) {
    console.error('❌ Review toggle error:', err);
    res.redirect('/user/admin/reviews');
  }
});

router.post('/admin/reviews/:id/delete', middleware.isLoggedIn, requireAdmin, async (req, res) => {
  try {
    await Review.findByIdAndDelete(req.params.id);
    res.redirect('/user/admin/reviews');
  } catch (err) {
    console.error('❌ Review delete error:', err);
    res.redirect('/user/admin/reviews');
  }
});

router.use('/', middleware.isNotLoggedIn, function(req, res, next) {
  next();
});

// Signup GET
router.get('/signup', async function(req, res, next) {
  try {
    var messages = req.flash('error');
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);

if (userData) {
  await sendFacebookCAPIEvent({
    eventName: "PageView",
    eventId: eventIdPageView,
    userData,
    eventSourceUrl: `https://${req.get("host")}${req.originalUrl}`,
    testEventCode: req.query.test_event_code || process.env.FB_TEST_EVENT_CODE
  });
}

    res.render('user/signup', {
      csrfToken: req.csrfToken(),
      messages: messages,
      req: req,
      metaEventIdPageView: eventIdPageView,
      user: req.user
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

// Signup POST
router.post('/signup', passport.authenticate('local-signup', {
  failureRedirect: '/user/signup',
  failureFlash: true
}), async function(req, res, next) {
  try {
    // 1. Generate Event ID
    const completeRegistrationEventId = generateEventId();
    req.session.completeRegistrationEventId = completeRegistrationEventId;
    
    // 2. LINK GUEST ORDERS (Crucial Step)
    if (req.user && req.user.numero) {
      await Order.linkGuestOrdersToUser(req.user.numero, req.user._id);
    }
    
    // 3. Send CAPI Event
    const userData = getCleanUserData(req);
    if (userData) {
      await sendFacebookCAPIEvent({
        eventName: "CompleteRegistration",
        eventId: completeRegistrationEventId,
        userData,
        customData: {
          content_name: "User Registration",
          status: "registered",
          currency: "DZD"
        },
        eventSourceUrl: `https://${req.get("host")}/user/signup`,
        testEventCode: process.env.FB_TEST_EVENT_CODE
      });
    }

    res.render('user/welcome', {
      csrfToken: req.csrfToken(),
      user: req.user,
      completeRegistrationEventId: completeRegistrationEventId,
      req: req
    });

  } catch (err) {
    console.error("❌ Signup Error:", err);
    res.redirect('/user/signup');
  }
});

router.get('/signin', async function(req, res, next) {
  try {
    var messages = req.flash('error');
    const eventIdPageView = generateEventId();
    const userData = getCleanUserData(req);

    if (userData) {
      await sendFacebookCAPIEvent({
        eventName: "PageView",
        eventId: eventIdPageView,
        userData,
        eventSourceUrl: `https://${req.get("host")}${req.originalUrl}`,
        testEventCode: req.query.test_event_code || process.env.FB_TEST_EVENT_CODE
      });
    }

    res.render('user/signin', {
      csrfToken: req.csrfToken(),
      messages: messages,
      req: req,
      metaEventIdPageView: eventIdPageView,
      user: req.user
    });
  } catch (err) {
    console.error("❌ Signin PageView Error:", err);
    res.redirect('/');
  }
});


// ==========================================
// 2. SIGNIN POST (Updated to Link Orders)
// ==========================================
router.post('/signin', passport.authenticate('local-signin', {
  failureRedirect: '/user/signin',
  failureFlash: true
}), async function(req, res, next) {
    
    // ✅ NEW LOGIC: When user successfully logs in, check for guest orders
    try {
        if (req.user && req.user.numero) {
            console.log(`👤 User logged in: ${req.user.firstName}. Checking for guest orders...`);
            
            // Execute the linking logic defined in your Order model
            const result = await Order.linkGuestOrdersToUser(req.user.numero, req.user._id);
            
            if (result.modifiedCount > 0) {
                console.log(`🔗 Successfully linked ${result.modifiedCount} previous guest orders to this account.`);
            }
        }
    } catch (error) {
        console.error("⚠️ Error linking guest orders on signin:", error);
        // We do not stop the login process if this fails
    }

    // Standard Redirect Logic
    if (req.session.oldUrl) {
      let oldUrl = req.session.oldUrl;
      req.session.oldUrl = null;
      res.redirect(oldUrl);
    } else {
      res.redirect('/user/profile');
    }
});

module.exports = router;
