using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace Project42_JWT.Model
{
    public class AppDbContext : DbContext
    {
      
        public DbSet<User> Users { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
    }
}
