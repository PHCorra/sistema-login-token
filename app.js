//require('dotenv').config();
/*imports*/
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
// models
import { User } from "./models/User.js";

dotenv.config();

const app = express();
const port = 3000;

// config JSON response
app.use(express.json());


// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'api testada com sucesso' });
})

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    // checking existence of user
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: 'User not found' });
    }

    res.status(200).json({ user });

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado' });
    }
    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret);

        next();
    } catch (err) {
        res.status(400).json({ msg: 'Token inválido' })
    }

}

// Register User 
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body

    //validations
    if (!name) {
        return res.status(422).json({ msg: 'Nome obrigatório' })
    }

    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' })
    }

    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória' })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem' })
    }

    // checking user
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ msg: 'Utilize outro email' });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })


    try {
        await user.save();

        res.status(201).json({ msg: 'Usuário criado com sucesso' })
    } catch (err) {
        console.log(err);
        res
            .status(500)
            .json({
                msg: 'erro no servidor'
            });
    }
})

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body
    // validations
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' });
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória' });
    }
    // check user existence
    const user = await User.findOne({ email: email }) // Comands to mongo

    if (!user) {
        return res.status(404).json({ msg: 'Usuario não existe' })
    }

    // checking password validations
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida' });
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,

        },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Erro no servidor' });
    }
})

// Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.9jpap.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
    )
    .then(() => {
        app.listen(port);
        console.log('banco conectado')
    }).catch((err) => {
        console.error(err);
    })


