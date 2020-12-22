const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const auth = require('../middleware/auth');

const User = require('../models/User');
const Contact = require('../models/Contact');
// @route    GET api/contacts
// @desc     Get all users contacts
// @access   Private
router.get('/', auth, async (req, res) => {
    try{
        const contacts = await Contact.find({ user: req.user.id }).sort({ date: -1});
        res.json(contacts);
    }catch{
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route    POST api/contacts
// @desc     Add a contact
// @access   Private
router.post(
    '/', 
    [ 
        auth, 
        [
            check('name', 'Please enter name').not().isEmpty(),
        ]
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()){
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, phone, type } = req.body;

        try{
            const newContact = new Contact({
                name,
                email, 
                phone, 
                type,
                user: req.user.id
            });

            const contact = await newContact.save();

            res.json(contact);
        }catch(err){
            console.error(err.message);
            res.status(500).send('Server error');
        }
    }
);

// @route    PUT api/contacts/:id
// @desc     Update a contact
// @access   Private
router.put('/:id', auth, async (req, res) => {
    const { name, email, phone, type } = req.body;
});

// @route    DELETE api/contacts/:id
// @desc     Update a contact
// @access   Public
router.delete('/:id', (req, res) => {
    res.send('Delete contact');
});

module.exports = router;