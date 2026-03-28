import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  UseGuards,
  Get,
  UnauthorizedException,
} from '@nestjs/common';
import { Response, Request } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { ConfigService } from '@nestjs/config';
import {
  LoginDto,
  LoginResponseDto,
  RefreshTokenDto,
  RefreshResponseDto,
  LogoutResponseDto,
  UserProfileDto,
} from './dto/auth.dto';

@ApiTags('auth')
@ApiBearerAuth('JWT-auth')
@ApiCookieAuth()
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Post('login')
  @ApiOperation({
    summary: 'Login with wallet address',
    description:
      'Authenticates a user by their wallet address and returns JWT tokens. Tokens are also set as HTTP-only cookies.',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 201,
    description: 'Successfully logged in',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Wallet address is required',
  })
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponseDto> {
    if (!body.walletAddress) {
      throw new UnauthorizedException('Wallet address is required');
    }

    const { accessToken, refreshToken, user } = await this.authService.login(
      body.walletAddress,
      req,
    );

    this.setCookies(res, accessToken, refreshToken);

    return {
      message: 'Logged in successfully',
      accessToken,
      refreshToken,
      user,
    };
  }

  @Post('refresh')
  @ApiOperation({
    summary: 'Refresh access token',
    description:
      'Refreshes the access token using a valid refresh token from cookies or request body',
  })
  @ApiBody({ type: RefreshTokenDto, required: false })
  @ApiResponse({
    status: 201,
    description: 'Tokens refreshed successfully',
    type: RefreshResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Refresh token not found',
  })
  async refresh(
    @Req() req: Request,
    @Body() body: RefreshTokenDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RefreshResponseDto> {
    const refreshToken = req.cookies['refresh_token'] || body.refreshToken;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const tokens = await this.authService.refreshTokens(refreshToken, req);
    this.setCookies(res, tokens.accessToken, tokens.refreshToken);

    return { message: 'Tokens refreshed successfully', ...tokens };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiOperation({
    summary: 'Logout user',
    description: 'Invalidates the current access token and clears authentication cookies',
  })
  @ApiResponse({
    status: 201,
    description: 'Successfully logged out',
    type: LogoutResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing token',
  })
  async logout(
    @Req() req: Request,
    @CurrentUser() user: any,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LogoutResponseDto> {
    const accessToken = req.cookies['access_token'] || req.headers.authorization?.split(' ')[1];

    if (accessToken) {
      await this.authService.logout(user.id, accessToken, user.sessionId);
    }

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({
    summary: 'Get current user profile',
    description: "Returns the authenticated user's profile information",
  })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing token',
  })
  getProfile(@CurrentUser() user: any): UserProfileDto {
    return user;
  }

  private setCookies(res: Response, accessToken: string, refreshToken: string) {
    const isProduction = this.configService.get('NODE_ENV') === 'production';

    // Access token cookie
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    // Refresh token cookie
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }
}
