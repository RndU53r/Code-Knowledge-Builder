using Microsoft.Azure.Functions.Worker;

public class Cleanup
{
    [Function("Cleanup")]
    public void Run([TimerTrigger("0 */5 * * * *")] object timer)
    {
    }

    [Function("Ingest")]
    public void Ingest([QueueTrigger("ingest-queue")] string message)
    {
    }
}
