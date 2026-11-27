package Shop::BaseRepo;
use strict;

sub new { return bless {}, shift }

sub save {
    my ($self, $item) = @_;
    return $item;
}

1;
