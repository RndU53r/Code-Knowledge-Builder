namespace Shop.Services
{
    public interface IOrderService
    {
        string Place(string item);
    }

    public class OrderService : IOrderService
    {
        private readonly OrderRepo _repo;

        public OrderService(OrderRepo repo)
        {
            _repo = repo;
        }

        public string Place(string item)
        {
            return _repo.Save(item);
        }
    }
}
