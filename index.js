const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = 4000;
const MONGO_URI =
    process.env.MONGO_URI || 'mongodb://localhost:27017/recipes_db';

app.use(cors({origin: process.env.CORS_ORIGIN || '*'}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {fileSize: 10 * 1024 * 1024},
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/'))
      return cb(new Error('Only image files are allowed'));
    cb(null, true);
  }
});

const recipeSchema = new mongoose.Schema({
  name: {type: String, required: true, trim: true},
  description: {type: String, default: '', trim: true},
  ingredients: {type: [String], default: []},
  instructions: {type: [String], default: []},
  image: {type: String, default: ''},
  imageType: {type: String, default: ''},
  favorite: {type: Boolean, default: false},
  createdAt: {type: Date, default: Date.now}
});

const Recipe = mongoose.model('Recipe', recipeSchema);

const formatRecipe = (doc) => {
  const obj = doc.toObject({versionKey: false});
  const {_id, image, imageType, ...rest} = obj;
  return {
    ...rest,
    _id: _id.toString(),
    image: image ? `data:${imageType};base64,${image}` : ''
  };
};

const validateRecipeBody = (requireName = true) => (req, res, next) => {
  const body = req.body ?? {};
  const name = body.name;
  const description = body.description;

  let ingredients;
  let instructions;

  try {
    ingredients = body.ingredients !== undefined ?
        JSON.parse(body.ingredients) :
        undefined;
    instructions = body.instructions !== undefined ?
        JSON.parse(body.instructions) :
        undefined;
  } catch {
    return res.status(400).json({
      message: 'ingredients and instructions must be valid JSON arrays',
      expected: {
        name: 'string',
        description: 'string',
        ingredients: 'array',
        instructions: 'array'
      }
    });
  }

  if (requireName && (!name || !name.trim()))
    return res.status(400).json({
      message: 'Recipe name is required',
      expected: {
        name: 'string',
        description: 'string',
        ingredients: 'array',
        instructions: 'array'
      }
    });

  if (name !== undefined && typeof name !== 'string')
    return res.status(400).json({message: 'name must be a string'});

  if (description !== undefined && typeof description !== 'string')
    return res.status(400).json({message: 'description must be a string'});

  if (ingredients !== undefined && !Array.isArray(ingredients))
    return res.status(400).json(
        {message: 'ingredients must be a JSON array string'});

  if (instructions !== undefined && !Array.isArray(instructions))
    return res.status(400).json(
        {message: 'instructions must be a JSON array string'});

  req.parsedBody = {name, description, ingredients, instructions};
  next();
};

app.get('/api/recipes/favorites', async (req, res) => {
  try {
    const docs = await Recipe.find({favorite: true});
    res.json(docs.map(formatRecipe));
  } catch (e) {
    res.status(500).json({message: 'Failed to fetch favorites'});
  }
});


app.put('/api/recipes/favorite', express.json(), async (req, res) => {
  const {id, shouldFavorite} = req.body ?? {};
  if (!id) return res.status(400).json({message: 'id is required'});
  if (typeof shouldFavorite !== 'boolean')
    return res.status(400).json({message: 'shouldFavorite must be a boolean'});

  try {
    const doc = await Recipe.findByIdAndUpdate(
        id, {$set: {favorite: shouldFavorite}}, {new: true});
    if (!doc) return res.status(404).json({message: 'Recipe not found'});
    res.json(formatRecipe(doc));
  } catch (e) {
    if (e.name === 'CastError')
      return res.status(400).json({message: 'Invalid recipe id'});
    res.status(500).json({message: 'Failed to update favorite'});
  }
});

app.get('/api/recipes', async (req, res) => {
  try {
    const docs = await Recipe.find();
    res.json(docs.map(formatRecipe));
  } catch (e) {
    res.status(500).json({message: 'Failed to fetch recipes'});
  }
});

app.get('/api/recipes/:id', async (req, res) => {
  try {
    const doc = await Recipe.findById(req.params.id);
    if (!doc) return res.status(404).json({message: 'Recipe not found'});
    res.json(formatRecipe(doc));
  } catch (e) {
    if (e.name === 'CastError')
      return res.status(400).json({message: 'Invalid recipe id'});
    res.status(500).json({message: 'Failed to fetch recipe'});
  }
});

app.post(
    '/api/recipes', upload.single('image'), validateRecipeBody(true),
    async (req, res) => {
      const {name, description, ingredients, instructions} = req.parsedBody;
      try {
        const doc = new Recipe({
          name,
          description: description ?? '',
          ingredients: ingredients ?? [],
          instructions: instructions ?? [],
          image: req.file ? req.file.buffer.toString('base64') : '',
          imageType: req.file ? req.file.mimetype : ''
        });
        await doc.save();
        res.status(201).json(formatRecipe(doc));
      } catch (e) {
        if (e.name === 'ValidationError')
          return res.status(400).json({message: e.message});
        res.status(500).json({message: 'Failed to create recipe'});
      }
    });

app.put(
    '/api/recipes/:id', upload.single('image'), validateRecipeBody(false),
    async (req, res) => {
      const {name, description, ingredients, instructions} = req.parsedBody;

      if (name !== undefined && !name.trim())
        return res.status(400).json({message: 'Recipe name cannot be empty'});

      const update = {};
      if (name !== undefined) update.name = name.trim();
      if (description !== undefined) update.description = description.trim();
      if (ingredients !== undefined) update.ingredients = ingredients;
      if (instructions !== undefined) update.instructions = instructions;
      if (req.file) {
        update.image = req.file.buffer.toString('base64');
        update.imageType = req.file.mimetype;
      }

      if (Object.keys(update).length === 0)
        return res.status(400).json({message: 'No fields to update'});

      try {
        const doc = await Recipe.findByIdAndUpdate(
            req.params.id, {$set: update}, {new: true, runValidators: true});
        if (!doc) return res.status(404).json({message: 'Recipe not found'});
        res.json(formatRecipe(doc));
      } catch (e) {
        if (e.name === 'CastError')
          return res.status(400).json({message: 'Invalid recipe id'});
        if (e.name === 'ValidationError')
          return res.status(400).json({message: e.message});
        res.status(500).json({message: 'Failed to update recipe'});
      }
    });

app.delete('/api/recipes/:id', async (req, res) => {
  try {
    const doc = await Recipe.findByIdAndDelete(req.params.id);
    if (!doc) return res.status(404).json({message: 'Recipe not found'});
    res.status(204).send();
  } catch (e) {
    if (e.name === 'CastError')
      return res.status(400).json({message: 'Invalid recipe id'});
    res.status(500).json({message: 'Failed to delete recipe'});
  }
});

app.use((err, req, res, next) => {
  if (err.message === 'Only image files are allowed')
    return res.status(400).json({message: err.message});
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(413).json({message: 'Image exceeds 10MB limit'});
  res.status(500).json({message: 'Internal server error'});
});

mongoose.connect(MONGO_URI)
    .then(() => {
      console.log('Connected to MongoDB');
      app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch((e) => {
      console.error('Failed to connect to MongoDB:', e);
      process.exit(1);
    });