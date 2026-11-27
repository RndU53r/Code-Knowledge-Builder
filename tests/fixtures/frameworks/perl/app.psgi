use Plack::Request;
my $app = sub {
    my $env = shift;
    my $req = Plack::Request->new($env);
    return [200, [], [$req->param('x')]];
};
