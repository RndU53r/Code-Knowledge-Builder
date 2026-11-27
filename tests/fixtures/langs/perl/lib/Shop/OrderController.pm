package Shop::OrderController;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use Shop::OrderService;

sub create ($self) {
    return $self->render(text => 'denied', status => 401) unless $self->authenticate;
    my $item = $self->param('item');
    my $svc = Shop::OrderService->new;
    $svc->place($item);
    return $self->render(text => 'ok');
}

sub authenticate ($self) {
    return defined $self->req->headers->authorization;
}

1;
