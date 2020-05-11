import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
  createSchema,
  ExtractDoc,
  ExtractProps,
  Type,
  typedModel,
} from 'ts-mongoose';
import { JWT_EXPIRES_IN, JWT_SECRET } from '../config/constants';
import {
  sanitizeMongoFields,
  sanitizeSpecifiedFields,
} from './../utils/sanitizeModel';

export enum Role {
  ADMIN = 'ADMIN',
  PLAYER = 'PLAYER',
}

// ************************ SCHEMA ************************ //
const UserSchema = createSchema(
  {
    displayName: Type.string({
      required: true,
      unique: true,
      trim: true,
      minlength: [2, 'Display name must contain at least 2 characters'],
      maxlength: [30, 'Display name must not contain more than 30 characters'],
    }),
    username: Type.string({
      unique: true,
      lowercase: true,
      required: true,
      trim: true,
      minlength: [2, 'Username must contain at least 2 characters'],
      maxlength: [30, 'Username must not contain more than 30 characters'],
      match: [
        /^[a-zA-Z0-9]+(?:[_-]?[a-zA-Z0-9])*$/,
        'Username can only contain letters, numbers, underscores and dashes',
      ],
    }),
    role: Type.string({
      enum: [Role.PLAYER],
      default: Role.PLAYER,
      required: true,
      uppercase: true,
    }),
    password: Type.string({
      required: true,
      minlength: [8, 'Password must contain at least 8 characters'],
      maxlength: [50, 'Password must not contain more than 50 characters'],
      match: [
        /^[a-zA-Z0-9]+(?:[_-]?[a-zA-Z0-9])*$/,
        'Password must only contain letters, numbers, underscores and dashes',
      ],
      select: false,
    }),
    passwordChangedAt: Type.date({ select: false }),
    // types of virtuals & custom functions go here
    // id comes from mongoose when virtuals are enabled
    ...({} as {
      id: string;
      isCorrectPassword(
        candidatePassword: string,
        userPassword: string
      ): Promise<boolean>;
      isPasswordChangedAfter(JWTTimestamp: Date): boolean;
      createPasswordResetToken(): string;
      signToken(): string;
    }),
  },
  {
    timestamps: true,
    toObject: { virtuals: true },
  }
);

// ************************ VIRTUALS ************************ // - add types to schema
UserSchema.virtual('passwordConfirm')
  .get(function (this: UserDoc & { _passwordConfirm: string }) {
    return this._passwordConfirm;
  })
  .set(function (this: UserDoc & { _passwordConfirm: string }, value: string) {
    this._passwordConfirm = value;
  });

// ************************ DOCUMENT MIDDLEWARE ************************ //

// Validate password confirmation
UserSchema.pre('validate', function (
  this: UserDoc & { passwordConfirm: string },
  next
) {
  if (!this.passwordConfirm)
    this.invalidate('passwordConfirm', 'passwordConfirm is required');
  else if (!/^[a-zA-Z0-9]+(?:[_-]?[a-zA-Z0-9])*$/.test(this.passwordConfirm))
    this.invalidate(
      'passwordConfirm',
      'Password must only contain letters, numbers, underscores and dashes'
    );
  else if (this.password !== this.passwordConfirm) {
    this.invalidate('passwordConfirm', 'Passwords do not match');
  }

  next();
});

// Hash Password on create
UserSchema.pre<UserDoc>('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);

  next();
});

// Hash password on update
UserSchema.pre<UserDoc>('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = new Date(Date.now() - 1000);

  next();
});

// ************************ INSTANCE METHODS ************************ // - add types to schema
UserSchema.methods.isCorrectPassword = async (
  candidatePassword: string,
  userPassword: string
) => await bcrypt.compare(candidatePassword, userPassword);

// Check if password was changed after the JWT token was sent
UserSchema.methods.isPasswordChangedAfter = function (JWTTimestamp: Date) {
  if (this.passwordChangedAt) {
    const changedTimeStamp = +this.passwordChangedAt.getTime() / 1000;
    return JWTTimestamp < new Date(changedTimeStamp);
  }

  return false;
};

UserSchema.methods.signToken = function () {
  return jwt.sign({ id: this.id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
};

UserSchema.plugin(sanitizeMongoFields);
UserSchema.plugin(sanitizeSpecifiedFields, [
  'password',
  'passwordConfirm',
  'passwordChangedAt',
]);

const User = typedModel('User', UserSchema, undefined, undefined, {
  // ************************ STATIC METHODS ************************ //
  findByUsername: function (username: string) {
    return this.findOne({ username });
  },
});

export default User;
export type UserDoc = ExtractDoc<typeof UserSchema>;
export type UserProps = ExtractProps<typeof UserSchema>;
