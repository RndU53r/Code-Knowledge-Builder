package Shop;
use Mojo::Base 'Mojolicious', -signatures;

sub startup ($self) {
    my $r = $self->routes;
    $r->post('/orders')->to('order#create');
}

1;
