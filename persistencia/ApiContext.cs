
using System.Reflection;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;


namespace Persistence;

public partial class ApiContext : DbContext
{
   public ApiContext()
   {
   }

   public ApiContext(DbContextOptions<ApiContext> options)
       : base(options)
   {
   }


   public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
   public virtual DbSet<Rol> Roles { get; set; }
   public virtual DbSet<User> Users { get; set; }
   public virtual DbSet<UserRol> UserRoles { get; set; }

   protected override void OnModelCreating(ModelBuilder modelBuilder)
   {
      base.OnModelCreating(modelBuilder);

      modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
   }
}