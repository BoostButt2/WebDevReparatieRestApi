using Xunit;
using Moq;
using System.Reflection.Metadata;
using Moq.EntityFrameworkCore;
using AimTrainerRestApi.Controllers;
using AimTrainerRestApi.Models;
using AimTrainerRestApi.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;

namespace RestApiTest
{
    public class UnitTest1
    {
        List<User> userList = new List<User>
            {
                new User
                {
                Userid = Guid.NewGuid(),
                Username = "Peter",
                Password = "Password2",
                Score = 5,
                Email = "peter@peter.peter",
                Role = "admin"
                },
                new User
                {
                Userid = Guid.NewGuid(),
                Username = "Pjotr",
                Password = "Password3",
                Score = 2,
                Email = "pjotr@pjotr.pjotr",
                Role = "player"
                }
            };


        [Fact]
        public async void GetAllUsers()
        {
            //Arrange
            var options = new DbContextOptionsBuilder<AimTrainerDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
            var _contextMock = new Mock<AimTrainerDbContext>(options);

            _contextMock.Setup(x => x.User).ReturnsDbSet(userList);
            var userController = new UserController(_contextMock.Object);
            var mockSet = new Mock<DbSet<User>>();
            mockSet.As<IQueryable<User>>().Setup(m => m.Provider).Returns(userList.AsQueryable().Provider);
            mockSet.As<IQueryable<User>>().Setup(m => m.Expression).Returns(userList.AsQueryable().Expression);
            mockSet.As<IQueryable<User>>().Setup(m => m.ElementType).Returns(userList.AsQueryable().ElementType);
            mockSet.As<IQueryable<User>>().Setup(m => m.GetEnumerator()).Returns(userList.GetEnumerator());
            //Act
            var result = (await userController.GetUser()).Value;

            //Assert
            Assert.NotNull(result);

            Assert.Equal(userList.Count, result.Count());
            Assert.Equal(userList[0].Username, result.ElementAt(0).Username);
            Assert.Equal(userList[1].Username, result.ElementAt(1).Username);
        }

        [Fact]
        public async void PostUser_CreatedAtActionResult()
        {
            //Arrange
            User newUser = new User{
                Userid = Guid.NewGuid(),
                Username = "Pietro",
                Password = "Password4",
                Score = 0,
                Email = "pietro@pietro.pietro",
                Role = "player"
            };
            var options = new DbContextOptionsBuilder<AimTrainerDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
            var _contextMock = new Mock<AimTrainerDbContext>(options);

            _contextMock.Setup(x => x.User).ReturnsDbSet(userList);
            var userController = new UserController(_contextMock.Object);
            var mockSet = new Mock<DbSet<User>>();
            mockSet.As<IQueryable<User>>().Setup(m => m.Provider).Returns(userList.AsQueryable().Provider);
            mockSet.As<IQueryable<User>>().Setup(m => m.Expression).Returns(userList.AsQueryable().Expression);
            mockSet.As<IQueryable<User>>().Setup(m => m.ElementType).Returns(userList.AsQueryable().ElementType);
            mockSet.As<IQueryable<User>>().Setup(m => m.GetEnumerator()).Returns(userList.GetEnumerator());

            //Act
            var result = (await userController.PostUser(newUser));

            //Assert
            var createdAtActionResult = Assert.IsType<CreatedAtActionResult>(result.Result);
            var createdUser = Assert.IsAssignableFrom<User>(createdAtActionResult.Value);
            Assert.Equal(newUser.Username, createdUser.Username);
            Assert.Equal(newUser.Email, createdUser.Email);
            Assert.Equal(newUser.Role, createdUser.Role);
        }

        [Fact]
        public async void PostUser_ProblemResult()
        {
            //Arrange
            User newUser = new User
            {
                Userid = Guid.NewGuid(),
                Username = "Pietro",
                Password = "Password4",
                Score = 0,
                Email = "pietrosEmail",
                Role = "player"
            };
            var options = new DbContextOptionsBuilder<AimTrainerDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
            var _contextMock = new Mock<AimTrainerDbContext>(options);

            _contextMock.Setup(x => x.User).ReturnsDbSet(userList);
            var userController = new UserController(_contextMock.Object);
            var mockSet = new Mock<DbSet<User>>();
            mockSet.As<IQueryable<User>>().Setup(m => m.Provider).Returns(userList.AsQueryable().Provider);
            mockSet.As<IQueryable<User>>().Setup(m => m.Expression).Returns(userList.AsQueryable().Expression);
            mockSet.As<IQueryable<User>>().Setup(m => m.ElementType).Returns(userList.AsQueryable().ElementType);
            mockSet.As<IQueryable<User>>().Setup(m => m.GetEnumerator()).Returns(userList.GetEnumerator());

            //Act
            var result = (await userController.PostUser(newUser));

            //Assert
            Assert.IsType<ObjectResult>(result.Result);
        }

        [Fact]
        public async void Delete_Authorized()
        {
            var token = GenerateJWT(0);
            var options = new DbContextOptionsBuilder<AimTrainerDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
            var _contextMock = new Mock<AimTrainerDbContext>(options);
            _contextMock.Setup(x => x.User).ReturnsDbSet(userList);
            var mockHttpContext = new DefaultHttpContext();
            mockHttpContext.Request.Headers["Authorization"] = "Bearer " + token;
            var controllerContext = new ControllerContext()
            {
                HttpContext = mockHttpContext
            };
            var userController = new UserController(_contextMock.Object);
            userController.ControllerContext = controllerContext;
            var mockSet = new Mock<DbSet<User>>();
            mockSet.As<IQueryable<User>>().Setup(m => m.Provider).Returns(userList.AsQueryable().Provider);
            mockSet.As<IQueryable<User>>().Setup(m => m.Expression).Returns(userList.AsQueryable().Expression);
            mockSet.As<IQueryable<User>>().Setup(m => m.ElementType).Returns(userList.AsQueryable().ElementType);
            mockSet.As<IQueryable<User>>().Setup(m => m.GetEnumerator()).Returns(userList.GetEnumerator());
            userController.ControllerContext.HttpContext.Request.Headers["Authorization"] = "Bearer " + token;

            var result = (await userController.DeleteUser(userList[1].Userid));

            Assert.IsType<NoContentResult>(result);
        }

        [Fact]
        public async void CheckAdmin_Success()
        {
            var token = GenerateJWT(0);
            var options = new DbContextOptionsBuilder<AimTrainerDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
            var _contextMock = new Mock<AimTrainerDbContext>(options);
            _contextMock.Setup(x => x.User).ReturnsDbSet(userList);
            var mockHttpContext = new DefaultHttpContext();
            mockHttpContext.Request.Headers["Authorization"] = "Bearer " + token;
            var controllerContext = new ControllerContext()
            {
                HttpContext = mockHttpContext
            };
            var userController = new UserController(_contextMock.Object);
            userController.ControllerContext = controllerContext;
            var mockSet = new Mock<DbSet<User>>();
            mockSet.As<IQueryable<User>>().Setup(m => m.Provider).Returns(userList.AsQueryable().Provider);
            mockSet.As<IQueryable<User>>().Setup(m => m.Expression).Returns(userList.AsQueryable().Expression);
            mockSet.As<IQueryable<User>>().Setup(m => m.ElementType).Returns(userList.AsQueryable().ElementType);
            mockSet.As<IQueryable<User>>().Setup(m => m.GetEnumerator()).Returns(userList.GetEnumerator());
            userController.ControllerContext.HttpContext.Request.Headers["Authorization"] = "Bearer " + token;

            var result = (await userController.cbeckAdmin());

            Assert.IsType<OkResult>(result.Result);
        }

        public string GenerateJWT(int index)
        {
            //https://localhost:7133/api/User/
            User user = userList[index];
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("Yh2k7QSu4l8CZg5p6X3Pna9L0Miy4D3Bvt0JVr87UcOj69Kqw5R2Nmf4FWs03Hdx");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("Username", user.Username), new Claim("Userid", user.Userid.ToString()), new Claim(ClaimTypes.Role, user.Role), new Claim("Email", user.Email) }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var fakeToken = tokenHandler.WriteToken(token);
            return fakeToken;
        }

    }
}