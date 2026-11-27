package Shop::Controller::Orders;
use Moose;
BEGIN { extends 'Catalyst::Controller'; }

sub create :Path('/orders') :Args(0) {
    my ($self, $c) = @_;
    my $item = $c->req->params->{item};
    my $out = `echo $item`;
}

sub list :Local {
    my ($self, $c) = @_;
}

1;
