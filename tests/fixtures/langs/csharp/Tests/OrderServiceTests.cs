namespace Shop.Tests
{
    public class OrderServiceTests
    {
        public void Places()
        {
            new OrderService(null).Place("a");
        }
    }
}
