using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Dtos;
using Domain.Entities;
using Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using API.Helpers;
using System.Threading.Tasks;


namespace API.Services
{
    public class UserService : IUserService
    {
        private readonly JWT _jwt;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPasswordHasher<User> _passwordHasher;

        public UserService(IUnitOfWork unitOfWork, IOptions<JWT> jwt, IPasswordHasher<User> passwordHasher)
        {
            _jwt = jwt.Value;
            _unitOfWork = unitOfWork;
            _passwordHasher = passwordHasher;
        }

        public async Task<string> RegisterAsync(RegisterDto registerDto)
        {
            var user = new User
            {
                Nombre = registerDto.Username,
                Email = registerDto.Email
            };

            user.Password = _passwordHasher.HashPassword(user, registerDto.Password); //Encrypt password

            var existingUser = _unitOfWork.Users
                                        .Find(u => u.Nombre.ToLower() == registerDto.Username.ToLower())
                                        .FirstOrDefault();

            if (existingUser == null)
            {
                var rolDefault = _unitOfWork.Roles
                                            .Find(u => u.Nombre == Authorization.rol_default.ToString())
                                            .FirstOrDefault();

                try
                {
                    if (rolDefault != null)
                    {
                        user.Roles.Add(rolDefault);
                    }

                    _unitOfWork.Users.Add(user);
                    await _unitOfWork.SaveAsync();

                    return $"User {registerDto.Username} has been registered successfully";
                }
                catch (Exception ex)
                {
                    var message = ex.Message;
                    return $"Error: {message}";
                }
            }
            else
            {
                return $"User {registerDto.Username} already registered.";
            }
        }

        public async Task<DataUserDto> GetTokenAsync(LoginDto model)
        {
            DataUserDto dataUserDto = new DataUserDto();
            var user = await _unitOfWork.Users.GetByUsernameAsync(model.Username);

            if (user == null)
            {
                dataUserDto.IsAuthenticated = false;
                dataUserDto.Message = $"User does not exist with username {model.Username}.";
                return dataUserDto;
            }

            var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

            if (result == PasswordVerificationResult.Success)
            {
                dataUserDto.IsAuthenticated = true;
                JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
                dataUserDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                dataUserDto.UserName = user.Nombre;
                dataUserDto.Roles = user.Roles.Select(u => u.Nombre).ToList();

                if (user.RefreshTokens.Any(a => a.IsActive))
                {
                    var activeRefreshToken = user.RefreshTokens.FirstOrDefault(a => a.IsActive);
                    if (activeRefreshToken != null)
                    {
                        dataUserDto.RefreshToken = activeRefreshToken.Token;
                        dataUserDto.RefreshTokenExpiration = activeRefreshToken.Expires;
                    }
                }
                else
                {
                    var refreshToken = CreateRefreshToken();
                    dataUserDto.RefreshToken = refreshToken.Token;
                    dataUserDto.RefreshTokenExpiration = refreshToken.Expires;
                    user.RefreshTokens.Add(refreshToken);
                    await _unitOfWork.SaveAsync();
                }

                return dataUserDto;
            }

            dataUserDto.IsAuthenticated = false;
            dataUserDto.Message = $"Incorrect credentials for user {user.Nombre}.";
            return dataUserDto;
        }

        public async Task<string> AddRoleAsync(AddRoleDto model)
        {
            var user = await _unitOfWork.Users.GetByUsernameAsync(model.Username);
            if (user == null)
            {
                return $"User {model.Username} does not exist.";
            }

            var result = _passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

            if (result == PasswordVerificationResult.Success)
            {
                var rolExists = _unitOfWork.Roles.Find(u => u.Nombre.ToLower() == model.Role.ToLower()).FirstOrDefault();

                if (rolExists != null)
                {
                    var userHasRole = user.Roles.Any(u => u.Id == rolExists.Id);

                    if (!userHasRole)
                    {
                        user.Roles.Add(rolExists);
                        _unitOfWork.Users.Update(user);
                        await _unitOfWork.SaveAsync();
                    }

                    return $"Role {model.Role} added to user {model.Username} successfully.";
                }

                return $"Role {model.Role} was not found.";
            }

            return $"Invalid credentials";
        }

        public async Task<DataUserDto> RefreshTokenAsync(string refreshToken)
        {
            var dataUserDto = new DataUserDto();

            var user = await _unitOfWork.Users.GetByRefreshTokenAsync(refreshToken);

            if (user == null)
            {
                dataUserDto.IsAuthenticated = false;
                dataUserDto.Message = $"Token is not assigned to any user.";
                return dataUserDto;
            }

            var refreshTokenEntity = user.RefreshTokens.FirstOrDefault(x => x.Token == refreshToken);

            if (refreshTokenEntity == null || !refreshTokenEntity.IsActive)
            {
                dataUserDto.IsAuthenticated = false;
                dataUserDto.Message = $"Token is not active.";
                return dataUserDto;
            }

            refreshTokenEntity.Revoked = DateTime.UtcNow;

            var newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            _unitOfWork.Users.Update(user);
            await _unitOfWork.SaveAsync();

            dataUserDto.IsAuthenticated = true;
            JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
            dataUserDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            dataUserDto.UserName = user.Nombre;
            dataUserDto.Email = user.Email;
            dataUserDto.Roles = user.Roles.Select(u => u.Nombre).ToList();
            dataUserDto.RefreshToken = newRefreshToken.Token;
            dataUserDto.RefreshTokenExpiration = newRefreshToken.Expires;

            return dataUserDto;
        }

        private RefreshToken CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(randomNumber);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomNumber),
                    Expires = DateTime.UtcNow.AddDays(10),
                    Created = DateTime.UtcNow
                };
            }
        }

        private JwtSecurityToken CreateJwtToken(User user)
        {
            var roles = user.Roles.Select(u => new Claim("roles", u.Nombre)).ToList();
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Nombre),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id.ToString())
            }
            .Union(roles);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
