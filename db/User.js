const { Sequelize, sequelize } = require('./db');

const User = sequelize.define('user', {
  auth0Id: Sequelize.STRING,
  name: Sequelize.STRING,
  email: Sequelize.STRING,
  admin: Sequelize.BOOLEAN,
});

User.associate = function(models) {
  User.hasMany(models.Pet, {
    foreignKey: 'userId',
    as: 'pets',
  });
};

module.exports = { User };
