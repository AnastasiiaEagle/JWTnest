import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterRequest } from './dto/register.dto';
import { hash, verify } from 'argon2';
import { ConfigService } from '@nestjs/config';
import type { JwtPayload } from './intefaces/jwt.interface';
import { JwtService } from '@nestjs/jwt';
import { LoginRequest } from './dto/login.dto';
import type { Request, Response } from 'express';
import { isDev } from 'src/utils/is-dev.util';

@Injectable()
export class AuthService {
    private readonly JWT_ACCESS_TOKEN_TTL: string
    private readonly JWT_REFRESH_TOKEN_TTL: string

    private readonly COOKIE_DOMAIN: string

    // private readonly jwtService: JwtService
    constructor( 
        private readonly prismaService: PrismaService, 
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,){
            this.JWT_ACCESS_TOKEN_TTL = configService.getOrThrow<string>('JWT_ACCESS_TOKEN_TTL')
            this.JWT_REFRESH_TOKEN_TTL = configService.getOrThrow<string>('JWT_REFRESH_TOKEN_TTL')
            this.COOKIE_DOMAIN = configService.getOrThrow<string>('COOKIE_DOMAIN')
        } 

    async register(res: Response, dto: RegisterRequest){
        const { name, email, password} = dto;

        const existUser = await this.prismaService.user.findUnique({
            where: {
                email,
            }
        });

        if(existUser) {
            throw new ConflictException('Такий користувач вже існує')
        }

        const user = await this.prismaService.user.create({
            data: {
                name,
                email,
                password: await hash(password)
            }
        });

        return this.auth(res, user.id)
    }

    async login(res: Response, dto: LoginRequest){
        const {email, password} = dto

        const user = await this.prismaService.user.findUnique({
            where: {
                email,
            },
            select: {
                id: true,
                password: true
            }
        })

        if(!user){
            throw new NotFoundException("Користувача не знайдено 1")
        }

        const isValidPassword = await verify(user.password, password);

        if(!isValidPassword){
            throw new NotFoundException("Користувача не знайдено 2")
        }

        return this.auth(res, user.id)
    }

    async refresh(req: Request, res: Response){   // перевірка авторизованого користувача на життя токену
        const refreshToken = req.cookies['refreshToken']
        if (!refreshToken || refreshToken === 'refreshToken') {
            throw new UnauthorizedException('Недійсний refresh-токен')
        }

        const payload: JwtPayload = await this.jwtService.verifyAsync(refreshToken)
        if(payload){
            const user = await this.prismaService.user.findUnique({
                where: {
                    id: payload.id
                },
                select: {
                    id: true
                }
            })

            if(!user) {
                throw new NotFoundException('Користувача не знайдено')
            }

            return this.auth(res, user.id)
        }
    }

    async logout(res: Response){  // вихід
        this.setCookie(res, 'refreshToken', new Date(0))
        return true
    }

    private auth(res: Response, id: string){
        const {accessToken, refreshToken} = this.generateToken(id)
        this.setCookie(res, refreshToken, new Date(Date.now() + 1000 * 60 * 60 * 24 * 7))

        return {accessToken}
    }

    private generateToken(id: string){
        const payload: JwtPayload = {id};
        const accessToken = this.jwtService.sign(payload, {expiresIn: this.JWT_ACCESS_TOKEN_TTL})
        const refreshToken = this.jwtService.sign(payload, {
            expiresIn: this.JWT_REFRESH_TOKEN_TTL
        })

        return {
            accessToken,
            refreshToken
        }
    }

    private setCookie(res: Response, value: string, expires: Date) {
        res.cookie("refreshToken", value, {
            httpOnly: true,
            domain: this.COOKIE_DOMAIN,
            expires,
            secure: !isDev(this.configService),
            sameSite: isDev(this.configService) ? 'none' : 'lax'
        })
    }
}
