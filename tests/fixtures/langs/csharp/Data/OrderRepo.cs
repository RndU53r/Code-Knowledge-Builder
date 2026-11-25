using System.Data.SqlClient;
using System.Net.Http;

namespace Shop.Data
{
    public class BaseRepo
    {
        public virtual string Save(string item)
        {
            return item;
        }
    }

    public class OrderRepo : BaseRepo
    {
        private readonly HttpClient _http;

        public override string Save(string item)
        {
            _http.GetAsync("http://billing/charge");
            var cmd = new SqlCommand($"SELECT * FROM orders WHERE id = {item}");
            return base.Save(item);
        }
    }
}
