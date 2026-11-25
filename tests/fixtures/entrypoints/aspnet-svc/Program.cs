var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/health", () => "ok");
app.MapPost("/webhook", HandleWebhook);

app.Run();

static IResult HandleWebhook(HttpRequest request)
{
    var body = request.Body;
    return Results.Ok();
}
