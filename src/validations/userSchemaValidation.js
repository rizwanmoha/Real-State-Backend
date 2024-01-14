import Joi from 'joi';

const userValidationSchema = Joi.object({
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  role: Joi.string().valid('User', 'Seller', 'Broker', 'Admin').required(),
  avatar: Joi.string().default("https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png"),
});

export { userValidationSchema };


