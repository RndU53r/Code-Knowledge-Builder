import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { Cron } from '@nestjs/schedule';
import * as fs from 'fs';

@Controller('users')
export class UsersController {
  @Get(':id')
  findOne(@Param('id') id: string) {
    return fs.readFileSync('/data/' + id);
  }

  @Post()
  create(@Body() body: any) {
    document.getElementById('x').innerHTML = body.name;
    return body;
  }

  @MessagePattern('user.created')
  onCreated(data: any) {
    return data;
  }

  @Cron('0 0 * * *')
  cleanup() {
    return 1;
  }
}
