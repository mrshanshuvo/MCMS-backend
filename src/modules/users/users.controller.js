const { getCollections } = require('../../config/db');

const upsertUser = async (req, res) => {
  const { email, name, photoURL, created_at, last_login } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  const updateDoc = {
    $setOnInsert: {
      name,
      photoURL,
      role: 'participant',
      created_at,
    },
    $set: {
      last_login,
    },
  };

  try {
    const { usersCollection } = getCollections();
    const result = await usersCollection.updateOne({ email }, updateDoc, {
      upsert: true,
    });
    res.send(result);
  } catch (error) {
    console.error('Error upserting user:', error);
    res.status(500).json({ error: 'Failed to upsert user.' });
  }
};

const updateLastLogin = async (req, res) => {
  const { email } = req.params;
  const { last_login } = req.body;

  if (req.user.email !== email) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (!last_login) {
    return res.status(400).json({ error: 'Missing last_login value.' });
  }

  try {
    const { usersCollection } = getCollections();
    const result = await usersCollection.updateOne({ email }, { $set: { last_login } });

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'Last login updated', result });
  } catch (error) {
    console.error('Error updating last_login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const getUserByEmail = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const { usersCollection } = getCollections();
    const user = await usersCollection.findOne({ email });
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
};

const updateUser = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { name, photoURL, phone, address } = req.body;

  const updateFields = {};
  if (name !== undefined) updateFields.name = name;
  if (photoURL !== undefined) updateFields.photoURL = photoURL;
  if (phone !== undefined) updateFields.phone = phone;
  if (address !== undefined) updateFields.address = address;

  try {
    const { usersCollection } = getCollections();
    const updateDoc = { $set: updateFields };
    const result = await usersCollection.updateOne({ email }, updateDoc);

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updatedUser = await usersCollection.findOne({ email });

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
};

const getUserRole = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const { usersCollection } = getCollections();
    const user = await usersCollection.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ role: user.role || 'participant' });
  } catch (error) {
    console.error('Error fetching user role:', error);
    res.status(500).json({ error: 'Failed to fetch user role' });
  }
};

module.exports = {
  upsertUser,
  updateLastLogin,
  getUserByEmail,
  updateUser,
  getUserRole,
};
