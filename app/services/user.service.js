const { ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");

class UserService {
  constructor(client) {
    this.User = client.db().collection("users");
  }

  extractUserData(payload) {
    const user = {
      name: payload.name,
      email: payload.email,
      password: payload.password,
      address: payload.address,
      phone: payload.phone,
    };

    Object.keys(user).forEach(
      (key) => user[key] == undefined && delete user[key]
    );
    return user;
  }

  async login(payload) {
    const { email } = payload;
    return await this.User.findOne({
      email: email,
    });
  }

  async register(payload) {
    const user = this.extractUserData(payload);
    const hashPassword = bcrypt.hashSync(user?.password, 10);
    const result = await this.User.insertOne({
      ...user,
      password: hashPassword,
    });
    return result.value;
  }

  async findByEmail(email) {
    return await this.User.findOne({
      email: email,
    });
  }

  async findById(id) {
    return await this.User.findOne({
      _id: ObjectId.isValid(id) ? new ObjectId(id) : null,
    });
  }

  async changePassword(userId, newPassword) {
    try {
      const user = await this.User.findOne({
        _id: ObjectId.isValid(userId) ? new ObjectId(userId) : null,
      });

      if (!user) {
        throw new Error("Người dùng không tồn tại");
      }
      const hashPassword = bcrypt.hashSync(newPassword, 10);
      const result = await this.User.findOneAndUpdate(
        { _id: user._id },
        { $set: { password: hashPassword } },
        { returnDocument: "after" }
      );
      return result;
    } catch (error) {
      throw new Error("Không thể thay đổi mật khẩu: " + error.message);
    }
  }
}

module.exports = UserService;
