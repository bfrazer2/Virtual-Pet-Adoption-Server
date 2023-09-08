require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const app = express();
app.use(logIncomingRequest);
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const jwksUri = `${process.env.AUTH0_BASE_URL}/.well-known/jwks.json`;
const client = jwksClient({ jwksUri });

async function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Authorization header missing or malformed');
  }

  const token = authHeader.split(' ')[1];

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.kid) {
    return res.status(401).send('Invalid token');
  }

  client.getSigningKey(decoded.header.kid, (err, key) => {
    if (err) {
      return res.status(500).send('Error fetching JWKS');
    }

    const signingKey = key.publicKey || key.rsaPublicKey;

    jwt.verify(token, signingKey, { algorithms: ["RS256"], audience: process.env.AUTH0_AUDIENCE, issuer: `${process.env.AUTH0_BASE_URL}/` }, (err, decoded) => {
      if (err) {
        return res.status(401).send('Token verification failed');
      }

      req.user = decoded;
      next();
    });
  });
}

const { User, Pet } = require('./db');

function logIncomingRequest(req, res, next) {
  console.log('======================');
  console.log(`Incoming Request: ${req.method} ${req.url}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  console.log('Body:', JSON.stringify(req.body, null, 2));
  console.log('======================');
  next();
}


// Application Level Middleware
const corsOptions = {
  origin: ['https://virtual-pet-adoption-client.onrender.com'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
};

const {
  AUTH0_AUDIENCE,
  AUTH0_BASE_URL,
} = process.env;

app.use(cors(corsOptions));
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'build')));


const isAdmin = (user) => {
if(user.admin == true) return user;
}

async function findOrCreateUser(jwtPayload) {
  try {
    let user = await User.findOne({ where: { auth0Id: jwtPayload.sub } });
    console.log('USER: ', user);
    if (!user) {
        user = new User({
            auth0Id: jwtPayload.sub,
        });
        await user.save();
    }
    return user;
  } catch (err) {
    throw err;
  }
}

app.get('/', (req, res) => {
  res.json({
    message: "Pet Adoption Center API",
    version: "1.0.0"
  });
});

// GET all pets route
app.get('/pets', validateToken, async (req, res, next) => {
  try {
      console.info('REQ.USER: ', req.user)
      const user = await findOrCreateUser(req.user);
      let pets;

      pets = await Pet.findAll({ where: { userId: user.id } });
      
      return res.send(pets);
  } catch (error) {
      console.error('get /pets error:', error);
      next(error);
  }
});


// Protected route to create a new pet
app.post('/pets', validateToken, async (req, res, next) => {
  const user = await findOrCreateUser(req.user);
  if (!user) {
    return res.status(401).send({ error: 'You must be logged in to create a pet!' });
  } else if (!user.id) {
    return res.status(400).send({error: "Couldn't find user id, invalid request."})
  } else {
    try {
      const { name, breed, age, weight, primaryColor, secondaryColor } = req.body;
      const newPet = await Pet.create(
        { name, 
          breed, 
          age, 
          weight, 
          primaryColor, 
          secondaryColor,
          hunger: 100,
          thirst: 100,
          friendship: 25, 
          favorite: false, 
          userId: user.id }
        );
      user.addPet(newPet);
      res.send(newPet);
    } catch (error) {
      console.error('post /pets error:', error);
      next(error);
    }
  }
});

//Protected route to get a pet and it's associated user
app.get('/pets/:id' , validateToken, async (req, res, next) => {
  const pet = await Pet.findOne({where: {id: req.params.id}, include: User}) 
  if (pet === null) {
    res.status(404).json({error: "Pet not found."})
  } else {
    res.json(pet)
  }
})

// Protected route to delete a pet
app.delete('/pets/:id', validateToken, async (req, res, next) => {
  try {
    const { id } = req.params;
    const user = await findOrCreateUser(req.user);
    const petExistCheck = await Pet.findOne({where: {id}})
    const petWithAuth = await Pet.findOne({ where: { id, userId: user.id } });
    if (!petExistCheck) {
      return res.status(404).send({ error: 'Pet not found.' });
    } else if (!petWithAuth && !isAdmin(user)) {
      return res.status(401).send({error: 'User not authorized to modify this pet.'})
    } else {
      await petWithAuth.destroy();
      res.send({ message: 'Pet deleted successfully.' });
    }
  } catch (error) {
    console.error('delete /pets/:id error:', error);
    next(error);
  }
});

// As a User, I want to edit entries in the database
app.put('/pets/:id', validateToken, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { name, age, breed, weight, hunger, thirst, friendship, favorite } = req.body;
    const user = await findOrCreateUser(req.user);
    let pet;

    //If the user is an admin, they may edit any pet in the db.
    if (isAdmin(user)) {
      pet = await Pet.findOne({ where: { id } });
    } else {
      pet = await Pet.findOne({ where: { id, userId: user.id } });
    }
    
    //If the pet is found based on the above criteria, the edits will apply.
    if (!pet) {
      return res.status(404).send({ error: 'Pet not found.' });
    } else {
      //Only update the parameters if they are provided
      if (name !== undefined) pet.name = name;
      if (age !== undefined) pet.age = age;
      if (breed !== undefined) pet.breed = breed;
      if (weight !== undefined) pet.weight = weight;
      if (hunger !== undefined) pet.hunger = hunger;
      if (thirst !== undefined) pet.thirst = thirst;
      if (friendship !== undefined) pet.friendship = friendship;
      if (favorite !== undefined) pet.favorite = favorite;
      await pet.save();
      return res.send({ message: 'Pet updated successfully!', pet: pet });
    }
  } catch (error) {
    console.error('put /pets/:id error:', error);
    return next(error);
  }
});

app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).send({ error: 'Invalid or missing token.' });
  }
  next(err);
});

app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

app.all('*', (req, res) => {
  res.send('Catch all route triggered');
});


module.exports = { app };