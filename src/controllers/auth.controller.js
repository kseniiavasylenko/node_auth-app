import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { pool } from '../db.js';
import * as mailService from '../services/mail.service.js';
import * as tokenService from '../services/token.service.js';

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Усі поля є обов’язковими' });
    }

    const candidateResult = await pool.query(
      'SELECT * FROM users WHERE email = $1;',
      [email],
    );

    if (candidateResult.rows.length > 0) {
      return res
        .status(400)
        .json({ message: 'Користувач із таким email вже існує' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const activationToken = uuidv4();

    const newUserResult = await pool.query(
      `INSERT INTO users (name, email, password, activation_token)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, is_activated;`,
      [name, email, hashedPassword, activationToken],
    );

    const user = newUserResult.rows[0];

    await mailService.sendActivationMail(
      email,
      `${process.env.CLIENT_URL}/api/activate/${activationToken}`,
    );

    return res.status(201).json({
      message: 'Реєстрація успішна. Перевірте пошту для активації акаунта.',
      user,
    });
  } catch (error) {
    return res.status(500).json({ message: 'Помилка сервера при реєстрації' });
  }
};

export const activate = async (req, res) => {
  try {
    const { activationToken } = req.params;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE activation_token = $1;',
      [activationToken],
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Невалідний токен активації' });
    }

    await pool.query(
      `UPDATE users
       SET is_activated = TRUE, activation_token = NULL
       WHERE activation_token = $1;`,
      [activationToken],
    );

    return res.json({ message: 'Акаунт успішно активовано' });
  } catch (error) {
    return res.status(500).json({ message: 'Помилка сервера при активації' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1;',
      [email],
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Користувача не знайдено' });
    }

    const user = userResult.rows[0];

    const isPassEquals = await bcrypt.compare(password, user.password);

    if (!isPassEquals) {
      return res.status(400).json({ message: 'Невірний пароль' });
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '30m' },
    );

    const refreshToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '30d' },
    );

    await tokenService.saveToken(user.id, refreshToken);

    res.cookie('refreshToken', refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });

    return res.json({
      accessToken,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    return res.status(500).json({ message: 'Помилка сервера при вході' });
  }
};

export const logout = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (refreshToken) {
      await tokenService.removeToken(refreshToken);
    }

    res.clearCookie('refreshToken');

    return res.json({ message: 'Вихід успішний' });
  } catch (error) {
    return res.status(500).json({ message: 'Помилка сервера при виході' });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1;',
      [email],
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Користувача не знайдено' });
    }

    const resetToken = uuidv4();

    await pool.query('UPDATE users SET reset_token = $1 WHERE email = $2;', [
      resetToken,
      email,
    ]);

    await mailService.sendActivationMail(
      email,
      `${process.env.CLIENT_URL}/reset-password/${resetToken}`,
    );

    return res.json({
      message: 'Лист для скидання пароля надіслано',
    });
  } catch (error) {
    return res
      .status(500)
      .json({ message: 'Помилка сервера при запиті скидання пароля' });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    const userResult = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1;',
      [resetToken],
    );

    if (userResult.rows.length === 0) {
      return res
        .status(400)
        .json({ message: 'Невалідний або застарілий токен скидання' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      `UPDATE users
       SET password = $1, reset_token = NULL
       WHERE reset_token = $2;`,
      [hashedPassword, resetToken],
    );

    return res.json({ message: 'Пароль успішно змінено' });
  } catch (error) {
    return res
      .status(500)
      .json({ message: 'Помилка сервера при скиданні пароля' });
  }
};

export const updateProfileName = async (req, res) => {
  try {
    const { name } = req.body;
    const userId = req.user.id;

    const updatedUserResult = await pool.query(
      `UPDATE users
       SET name = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id, name, email;`,
      [name, userId],
    );

    return res.json(updatedUserResult.rows[0]);
  } catch (error) {
    return res
      .status(500)
      .json({ message: 'Помилка сервера при оновленні імені' });
  }
};

export const updatePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    const userResult = await pool.query('SELECT * FROM users WHERE id = $1;', [
      userId,
    ]);

    const user = userResult.rows[0];

    const isPassEquals = await bcrypt.compare(oldPassword, user.password);

    if (!isPassEquals) {
      return res.status(400).json({ message: 'Невірний старий пароль' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      `UPDATE users
       SET password = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2;`,
      [hashedPassword, userId],
    );

    return res.json({ message: 'Пароль успішно оновлено' });
  } catch (error) {
    return res
      .status(500)
      .json({ message: 'Помилка сервера при оновленні пароля' });
  }
};

export const updateEmail = async (req, res) => {
  try {
    const { email } = req.body;
    const userId = req.user.id;

    const activationToken = uuidv4();

    await pool.query(
      `UPDATE users
       SET email = $1, is_activated = FALSE,
           activation_token = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3;`,
      [email, activationToken, userId],
    );

    await mailService.sendActivationMail(
      email,
      `${process.env.CLIENT_URL}/api/activate/${activationToken}`,
    );

    return res.json({
      message: 'Email оновлено. Перевірте нову пошту для активації.',
    });
  } catch (error) {
    return res
      .status(500)
      .json({ message: 'Помилка сервера при оновленні email' });
  }
};
