import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterRequest } from './dto/register.dto';
import { hash } from 'argon2';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './intefaces/jwt.interface';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    private readonly JWT_SECRET: string
    private readonly JWT_ACCESS_TOKEN_TTL: string
    private readonly JWT_REFRESH_TOKEN_TTL: string

    private readonly jwtService: JwtService
    constructor( 
        private readonly prismaService: PrismaService, 
        private readonly configService: ConfigService){
            this.JWT_SECRET = configService.getOrThrow<string>('JWT_SECRET')
            this.JWT_ACCESS_TOKEN_TTL = configService.getOrThrow<string>('JWT_ACCESS_TOKEN_TTL')
            this.JWT_REFRESH_TOKEN_TTL = configService.getOrThrow<string>('JWT_REFRESH_TOKEN_TTL')
        }

    async register(dto: RegisterRequest){
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

        return this.generateToken(user.id);
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
}
