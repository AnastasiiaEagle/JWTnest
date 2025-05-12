import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterRequest } from './dto/register.dto';
import { LoginRequest } from './dto/login.dto';
import type { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

    @HttpCode(HttpStatus.CREATED)
    @Post('register')
    async register (@Res({passthrough: true}) res: Response, @Body() dto: RegisterRequest){
      return await this.authService.register(res, dto);
    }

    @HttpCode(HttpStatus.OK)
    @Get('login')
    async login (@Res({passthrough: true}) res: Response, @Body() dto: LoginRequest){
      return await this.authService.login(res, dto);
    }

    @HttpCode(HttpStatus.OK)
    @Get('refresh')
    async refresh (@Req() req: Request, @Res({passthrough: true}) res: Response){
      return await this.authService.refresh(req, res);
    }

    @HttpCode(HttpStatus.OK)
    @Get('logout')
    async logout (@Res({passthrough: true}) res: Response){
      return await this.authService.logout( res);
    }
}
