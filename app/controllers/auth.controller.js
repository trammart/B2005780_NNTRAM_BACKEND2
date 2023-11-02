const ApiError = require("../api-error");
const UserService = require("../services/user.service");
const MongoDB = require("../utils/mongodb.util");
const bcrypt = require("bcrypt");

exports.login = async (req, res, next) => {
  if (!req.body?.email) {
    return next(new ApiError(400, "Email không được để trống."));
  }
  if (!req.body?.password) {
    return next(new ApiError(400, "Mật khẩu không được để trống."));
  }

  try {
    const userService = new UserService(MongoDB.client);
    const { email, password } = req.body;

    const document = await userService.login(req.body);

    if (!document) {
      return next(new ApiError(404, "Tài khoản hoặc mật khẩu không đúng."));
    } else {
      const comparePassword = bcrypt.compareSync(password, document?.password);
      if (!comparePassword) {
        return next(new ApiError(404, "Tài khoản hoặc mật khẩu không đúng."));
      }
    }

    return res.send(document);
  } catch (error) {
    return next(
      new ApiError(500, "An error occurred while creating account")
    );
  }
};

exports.register = async (req, res, next) => {
  if (!req.body?.name) {
    return next(new ApiError(400, "Họ tên không được để trống."));
  }
  if (!req.body?.email) {
    return next(new ApiError(400, "Email không được để trống."));
  }
  if (!req.body?.phone) {
    return next(new ApiError(400, "Số điện thoại không được để trống."));
  }
  if (!req.body?.address) {
    return next(new ApiError(400, "Địa chỉ không được để trống."));
  }
  if (!req.body?.password) {
    return next(new ApiError(400, "Mật khẩu không được để trống."));
  }
  if (!req.body?.confirmPassword) {
    return next(new ApiError(400, "Mật khẩu nhập lại không được để trống."));
  }
  if (req.body?.password !== req.body?.confirmPassword) {
    return next(new ApiError(400, "Mật khẩu nhập lại không trùng khớp."));
  }

  try {
    const userService = new UserService(MongoDB.client);
    const existedUser = await userService.findByEmail(req.body?.email);
    if (existedUser) {
      return next(new ApiError(400, "Tài khoản đã tồn tại."));
    }
    const document = await userService.register(req.body);
    return res.send(document);
  } catch (error) {
    console.log(error);
    return next(
      new ApiError(500, "An error occurred while creating the account")
    );
  }
};

exports.findByEmail = async (req, res, next) => {
  try {
    const userService = new UserService(MongoDB.client);
    const document = await userService.findByEmail(req.params.id);
    if (!document) {
      return next(new ApiError(404, "Không tìm thấy tài khoản"));
    }
    return res.send(document);
  } catch (error) {
    return next(
      new ApiError(500, `Error retrieving user with email = ${req.params.id}`)
    );
  }
};

exports.findById = async (req, res, next) => {
  try {
    const userService = new UserService(MongoDB.client);
    const document = await userService.findById(req.params.id);
    if (!document) {
      return next(new ApiError(404, "Không tìm thấy tài khoản"));
    }
    return res.send(document);
  } catch (error) {
    return next(
      new ApiError(500, `Error retrieving user with email = ${req.params.id}`)
    );
  }
};

exports.changePassword = async (req, res, next) => {
  try {
    if (!req.body?.currentPassword) {
      return next(new ApiError(400, "Vui lòng nhập mật khẩu hiện tại."));
    }
    if (!req.body?.newPassword) {
      return next(new ApiError(400, "Mật khẩu mới không được để trống."));
    }

    const userId = req.params.id;
    const currentPassword = req.body.currentPassword;
    const userService = new UserService(MongoDB.client);
    const user = await userService.findById(userId);

    const isCurrentPasswordValid = await bcrypt.compare(currentPassword,user.password);
    if (!isCurrentPasswordValid) {
      return next(new ApiError(400, "Mật khẩu hiện tại không đúng."));
    }
    const newPassword = req.body.newPassword;
    const updatedUser = await userService.changePassword(userId, newPassword);
    if (!updatedUser) {
      return next(new ApiError(500, "Không thể thay đổi mật khẩu."));
    }
    return res.send("Mật khẩu đã được thay đổi thành công.");
  } catch (error) {
    return next(new ApiError(500,"An error occurred while changing the password: " + error.message));
  }
};
