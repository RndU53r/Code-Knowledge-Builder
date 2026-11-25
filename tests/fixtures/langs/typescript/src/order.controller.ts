import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { OrderService } from './order.service';

@Controller('orders')
export class OrderController {
  constructor(private readonly service: OrderService) {}

  @Post()
  @UseGuards(AuthGuard)
  create(@Body() body: any) {
    return this.service.place(body);
  }
}
