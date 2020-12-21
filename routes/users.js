const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');

const User = require('../models/User');

// @route    POST api/users
// @desc     Register a user
// @access   Public
router.post('/', [
    check('name', 'Please enter name')
        .not()
        .isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
        'password', 
        'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 })
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()){
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password} = req.body;

        try{
            let user = await User.findOne({ email });

            if(user){
                return res.status(400).json({ msg: 'User already exists' });
            }

            user = new User({
                name, email, password // the same as name: name, email: email...
            });

            //encript password
            const salt = await bcrypt.genSalt(10); // how secure the salt is
            user.password = await bcrypt.hash(password, salt);
            try{
                await user.save();
            }
            catch{
                console.log(err);
            }

            const payload = { // to be used while the user is logged in
                user: {
                    id: user.id
                }
            }

            jwt.sign(
               payload, 
               config.get('jwtSecret'), 
               { expiresIn: 360000 }, // seconds
               (err, token) => {
                   if(err) throw err;
                   res.json({ token });
               }
            );
        } catch(err){
            res.status(500).send('Server Error');
        }
    }
);

module.exports = router;