import { IsEmail, IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator";

export class LoginRequest {
    @IsString({message: "Пошта має бути строкою"})
    @IsNotEmpty({ message: "Пошта обов'язкова для заповнення"})
    @IsEmail({},{message: "Некоректний формат пошти"})
    email: string;

    @IsString({message: "Пароль має бути строкою"})
    @IsNotEmpty({ message: "Пароль обов'язковий для заповнення"})
    @MinLength(6, {message: "Пароль має мітити не менше 6 символів"})
    @MaxLength(128, {message: "Максимальна довжина пароля 128 символів"})
    password: string;
}