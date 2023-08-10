const { Pet } = require('./Pet')
const { User } = require('./User');
const { sequelize, Sequelize } = require('./db');

Pet.belongsTo(User, {foreignKey: 'userId'});
User.hasMany(Pet)

module.exports = {
    User,
    Pet,
    Sequelize,
    sequelize
};