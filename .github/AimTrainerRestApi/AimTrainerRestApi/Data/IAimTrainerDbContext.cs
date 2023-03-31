using AimTrainerRestApi.Models;
using Microsoft.EntityFrameworkCore;

namespace AimTrainerRestApi.Data
{
    public interface IAimTrainerDbContext
    {
        public DbSet<AimTrainerRestApi.Models.User> User { get; set; }
    }
}
