const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;

app.use(cors({origin: process.env.CORS_ORIGIN || '*'}));
app.use(express.json());

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minlength: 3,
    maxlength: 32
  },
  fullName: {type: String, required: true, trim: true, maxlength: 80},
  pin: {type: String, required: true},
  balance: {type: Number, default: 1000.00},
  role: {type: String, enum: ['user', 'admin'], default: 'user'},
  status: {type: String, enum: ['active', 'suspended'], default: 'active'},
  createdAt: {type: Date, default: Date.now}
});

const transactionSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'transfer_out', 'transfer_in'],
    required: true
  },
  amount: {type: Number, required: true, min: 0.01},
  balanceAfter: {type: Number, required: true},
  userId: {type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true},
  counterpartyId:
      {type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null},
  counterpartyUsername: {type: String, default: null},
  note: {type: String, default: '', trim: true, maxlength: 200},
  createdAt: {type: Date, default: Date.now}
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

const formatUser = (doc) => {
  const obj = doc.toObject({versionKey: false});
  const {pin, ...rest} = obj;
  return {...rest, _id: obj._id.toString()};
};

const formatTx = (doc) => {
  const obj = doc.toObject ? doc.toObject({versionKey: false}) : doc;
  return {
    ...obj,
    _id: obj._id.toString(),
    userId: obj.userId.toString(),
    counterpartyId: obj.counterpartyId ? obj.counterpartyId.toString() : null
  };
};

const validateUsername = (u) => /^[a-z0-9_]{3,32}$/.test(u);
const validatePin = (p) => /^\d{4,6}$/.test(p);
const validateAmount = (a) =>
    typeof a === 'number' && Number.isFinite(a) && a >= 0.01 && a <= 1_000_000;

const authMiddleware = async (req, res, next) => {
  const username = req.headers['x-username'];
  if (!username) return res.status(401).json({message: 'Unauthorized'});
  try {
    const user = await User.findOne({username: username.toLowerCase()});
    if (!user) return res.status(401).json({message: 'Unauthorized'});
    if (user.status === 'suspended')
      return res.status(403).json({message: 'Account suspended'});
    req.user = user;
    next();
  } catch {
    res.status(500).json({message: 'Auth failed'});
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({message: 'Admin access required'});
  next();
};

app.post('/api/auth/register', async (req, res) => {
  const {username, fullName, pin} = req.body ?? {};

  if (!username || typeof username !== 'string' ||
      !validateUsername(username.trim().toLowerCase()))
    return res.status(400).json({
      message:
          'Username must be 3-32 characters: letters, numbers, underscores only'
    });
  if (!fullName || typeof fullName !== 'string' || !fullName.trim())
    return res.status(400).json({message: 'Full name is required'});
  if (fullName.trim().length > 80)
    return res.status(400).json(
        {message: 'Full name must be 80 characters or fewer'});
  if (!pin || typeof pin !== 'string' || !validatePin(pin))
    return res.status(400).json({message: 'PIN must be 4-6 digits'});

  try {
    const exists =
        await User.findOne({username: username.trim().toLowerCase()});
    if (exists)
      return res.status(409).json({message: 'Username already taken'});

    const hashed = await bcrypt.hash(pin, 12);
    const user = new User({
      username: username.trim().toLowerCase(),
      fullName: fullName.trim(),
      pin: hashed
    });
    await user.save();

    res.status(201).json({user: formatUser(user)});
  } catch (e) {
    if (e.code === 11000)
      return res.status(409).json({message: 'Username already taken'});
    res.status(500).json({message: 'Registration failed'});
  }
});

app.post('/api/auth/login', async (req, res) => {
  const {username, pin} = req.body ?? {};

  if (!username || typeof username !== 'string' || !username.trim())
    return res.status(400).json({message: 'Username is required'});
  if (!pin || typeof pin !== 'string' || !pin.trim())
    return res.status(400).json({message: 'PIN is required'});

  try {
    const user = await User.findOne({username: username.trim().toLowerCase()});
    if (!user)
      return res.status(401).json({message: 'Invalid username or PIN'});
    if (user.status === 'suspended')
      return res.status(403).json(
          {message: 'Account suspended. Contact support.'});

    const match = await bcrypt.compare(pin, user.pin);
    if (!match)
      return res.status(401).json({message: 'Invalid username or PIN'});

    res.json({user: formatUser(user)});
  } catch {
    res.status(500).json({message: 'Login failed'});
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json(formatUser(req.user));
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const {fullName, currentPin, newPin} = req.body ?? {};
  const update = {};

  if (fullName !== undefined) {
    if (typeof fullName !== 'string' || !fullName.trim())
      return res.status(400).json({message: 'Full name cannot be empty'});
    if (fullName.trim().length > 80)
      return res.status(400).json(
          {message: 'Full name must be 80 characters or fewer'});
    update.fullName = fullName.trim();
  }

  if (newPin !== undefined) {
    if (!currentPin || typeof currentPin !== 'string')
      return res.status(400).json(
          {message: 'Current PIN is required to set a new PIN'});
    if (!validatePin(newPin))
      return res.status(400).json({message: 'New PIN must be 4-6 digits'});

    const match = await bcrypt.compare(currentPin, req.user.pin);
    if (!match)
      return res.status(401).json({message: 'Current PIN is incorrect'});
    update.pin = await bcrypt.hash(newPin, 12);
  }

  if (Object.keys(update).length === 0)
    return res.status(400).json({message: 'No fields to update'});

  try {
    const user = await User.findByIdAndUpdate(
        req.user._id, {$set: update}, {new: true, runValidators: true});
    res.json(formatUser(user));
  } catch {
    res.status(500).json({message: 'Failed to update profile'});
  }
});

app.get('/api/account/balance', authMiddleware, async (req, res) => {
  res.json({balance: req.user.balance});
});

app.post('/api/account/deposit', authMiddleware, async (req, res) => {
  const {amount, note} = req.body ?? {};

  if (!validateAmount(amount))
    return res.status(400).json(
        {message: 'Amount must be a number between ₱0.01 and ₱1,000,000'});
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.status(400).json(
        {message: 'Note must be 200 characters or fewer'});

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const user = await User.findById(req.user._id).session(session);
    user.balance = parseFloat((user.balance + amount).toFixed(2));
    await user.save({session});

    const tx = new Transaction({
      type: 'deposit',
      amount,
      balanceAfter: user.balance,
      userId: user._id,
      note: note?.trim() ?? ''
    });
    await tx.save({session});
    await session.commitTransaction();

    res.status(201).json({balance: user.balance, transaction: formatTx(tx)});
  } catch {
    await session.abortTransaction();
    res.status(500).json({message: 'Deposit failed'});
  } finally {
    session.endSession();
  }
});

app.post('/api/account/withdraw', authMiddleware, async (req, res) => {
  const {amount, note} = req.body ?? {};

  if (!validateAmount(amount))
    return res.status(400).json(
        {message: 'Amount must be a number between ₱0.01 and ₱1,000,000'});
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.status(400).json(
        {message: 'Note must be 200 characters or fewer'});

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const user = await User.findById(req.user._id).session(session);
    if (user.balance < amount) {
      await session.abortTransaction();
      return res.status(400).json({message: 'Insufficient balance'});
    }

    user.balance = parseFloat((user.balance - amount).toFixed(2));
    await user.save({session});

    const tx = new Transaction({
      type: 'withdrawal',
      amount,
      balanceAfter: user.balance,
      userId: user._id,
      note: note?.trim() ?? ''
    });
    await tx.save({session});
    await session.commitTransaction();

    res.status(201).json({balance: user.balance, transaction: formatTx(tx)});
  } catch {
    await session.abortTransaction();
    res.status(500).json({message: 'Withdrawal failed'});
  } finally {
    session.endSession();
  }
});

app.post('/api/account/transfer', authMiddleware, async (req, res) => {
  const {toUsername, amount, note} = req.body ?? {};

  if (!toUsername || typeof toUsername !== 'string' || !toUsername.trim())
    return res.status(400).json({message: 'Recipient username is required'});
  if (!validateAmount(amount))
    return res.status(400).json(
        {message: 'Amount must be a number between ₱0.01 and ₱1,000,000'});
  if (note && (typeof note !== 'string' || note.length > 200))
    return res.status(400).json(
        {message: 'Note must be 200 characters or fewer'});

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const sender = await User.findById(req.user._id).session(session);
    if (sender.username === toUsername.trim().toLowerCase()) {
      await session.abortTransaction();
      return res.status(400).json({message: 'Cannot transfer to yourself'});
    }

    const receiver =
        await User.findOne({username: toUsername.trim().toLowerCase()})
            .session(session);
    if (!receiver) {
      await session.abortTransaction();
      return res.status(404).json({message: 'Recipient not found'});
    }
    if (receiver.status === 'suspended') {
      await session.abortTransaction();
      return res.status(400).json({message: 'Recipient account is suspended'});
    }
    if (sender.balance < amount) {
      await session.abortTransaction();
      return res.status(400).json({message: 'Insufficient balance'});
    }

    sender.balance = parseFloat((sender.balance - amount).toFixed(2));
    receiver.balance = parseFloat((receiver.balance + amount).toFixed(2));
    await sender.save({session});
    await receiver.save({session});

    const trimmedNote = note?.trim() ?? '';
    const txOut = new Transaction({
      type: 'transfer_out',
      amount,
      balanceAfter: sender.balance,
      userId: sender._id,
      counterpartyId: receiver._id,
      counterpartyUsername: receiver.username,
      note: trimmedNote
    });
    const txIn = new Transaction({
      type: 'transfer_in',
      amount,
      balanceAfter: receiver.balance,
      userId: receiver._id,
      counterpartyId: sender._id,
      counterpartyUsername: sender.username,
      note: trimmedNote
    });
    await txOut.save({session});
    await txIn.save({session});
    await session.commitTransaction();

    res.status(201).json(
        {balance: sender.balance, transaction: formatTx(txOut)});
  } catch {
    await session.abortTransaction();
    res.status(500).json({message: 'Transfer failed'});
  } finally {
    session.endSession();
  }
});

app.get('/api/account/history', authMiddleware, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  const skip = (page - 1) * limit;

  try {
    const [txs, total] = await Promise.all([
      Transaction.find({userId: req.user._id})
          .sort({createdAt: -1})
          .skip(skip)
          .limit(limit),
      Transaction.countDocuments({userId: req.user._id})
    ]);
    res.json({
      transactions: txs.map(formatTx),
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch {
    res.status(500).json({message: 'Failed to fetch history'});
  }
});

app.get('/api/users/search', authMiddleware, async (req, res) => {
  const q = req.query.q?.trim().toLowerCase();
  if (!q || q.length < 2)
    return res.status(400).json(
        {message: 'Query must be at least 2 characters'});

  try {
    const users = await User
                      .find({
                        username: {$regex: q, $options: 'i'},
                        _id: {$ne: req.user._id}
                      })
                      .limit(10)
                      .select('username fullName');

    res.json(users.map(u => ({
                         _id: u._id.toString(),
                         username: u.username,
                         fullName: u.fullName
                       })));
  } catch {
    res.status(500).json({message: 'Search failed'});
  }
});

app.get('/api/users/lookup/:username', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne(
        {username: req.params.username.trim().toLowerCase()});
    if (!user) return res.status(404).json({message: 'User not found'});
    res.json({
      _id: user._id.toString(),
      username: user.username,
      fullName: user.fullName
    });
  } catch {
    res.status(500).json({message: 'Lookup failed'});
  }
});

app.get(
    '/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 30));
      const skip = (page - 1) * limit;

      try {
        const [users, total] = await Promise.all([
          User.find().sort({createdAt: -1}).skip(skip).limit(limit),
          User.countDocuments()
        ]);
        res.json({
          users: users.map(formatUser),
          total,
          page,
          pages: Math.ceil(total / limit)
        });
      } catch {
        res.status(500).json({message: 'Failed to fetch users'});
      }
    });

app.put(
    '/api/admin/users/:id/status', authMiddleware, adminMiddleware,
    async (req, res) => {
      const {status} = req.body ?? {};
      if (!['active', 'suspended'].includes(status))
        return res.status(400).json(
            {message: 'Status must be active or suspended'});

      try {
        if (req.params.id === req.user._id.toString())
          return res.status(400).json(
              {message: 'Cannot change your own status'});
        const user = await User.findByIdAndUpdate(
            req.params.id, {$set: {status}}, {new: true});
        if (!user) return res.status(404).json({message: 'User not found'});
        res.json(formatUser(user));
      } catch (e) {
        if (e.name === 'CastError')
          return res.status(400).json({message: 'Invalid user id'});
        res.status(500).json({message: 'Failed to update status'});
      }
    });

app.get(
    '/api/admin/transactions', authMiddleware, adminMiddleware,
    async (req, res) => {
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 30));
      const skip = (page - 1) * limit;

      try {
        const [txs, total] = await Promise.all([
          Transaction.find().sort({createdAt: -1}).skip(skip).limit(limit),
          Transaction.countDocuments()
        ]);
        res.json({
          transactions: txs.map(formatTx),
          total,
          page,
          pages: Math.ceil(total / limit)
        });
      } catch {
        res.status(500).json({message: 'Failed to fetch transactions'});
      }
    });

app.use((err, req, res, next) => {
  res.status(500).json({message: 'Internal server error'});
});

mongoose.connect(MONGO_URI, {dbName: 'bank_db'})
    .then(() => {
      console.log('Connected to MongoDB');
      app.listen(
          PORT, () => console.log(`GreenBank API running on port ${PORT}`));
    })
    .catch((e) => {
      console.error('Failed to connect to MongoDB:', e);
      process.exit(1);
    });